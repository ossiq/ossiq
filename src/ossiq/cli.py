"""Console script for ossiq-cli."""

import importlib.metadata
import logging
import sys
from pathlib import Path
from typing import Annotated, Literal

try:
    import typer
    from rich.console import Console
except ImportError:
    print(
        "ossiq CLI requires the 'cli' extra. Install with: pip install 'ossiq[cli]'",
        file=sys.stderr,
    )
    sys.exit(1)

from ossiq.adapters.package_managers.helpers.helpers_npm import npm_helpers_app
from ossiq.adapters.package_managers.helpers.helpers_uv import uv_helpers_app
from ossiq.clients import install_requests_cache
from ossiq.commands.export import CommandExportOptions, commnad_export
from ossiq.commands.package import CommandInfoOptions, command_info
from ossiq.commands.plan import (
    CommandPlanOptions,
    check_override_ignore_conflict,
    command_apply,
    command_plan,
    parse_override_specs,
)
from ossiq.commands.status import CommandStatusOptions, command_status
from ossiq.domain.common import UserInterfaceType
from ossiq.messages import (
    ARGS_HELP_CACHE_DESTINATION,
    ARGS_HELP_CACHE_TTL,
    ARGS_HELP_COOLDOWN_PERIOD,
    ARGS_HELP_CUTOFF_DATE,
    ARGS_HELP_DEBUG,
    ARGS_HELP_GITHUB_TOKEN,
    ARGS_HELP_OUTPUT,
    ARGS_HELP_PRESENTATION,
    HELP_IGNORE_PACKAGE,
    HELP_LAG_THRESHOULD,
    HELP_OUTPUT_FORMAT,
    HELP_OVERRIDE_PACKAGE,
    HELP_PACKAGE_NAME,
    HELP_PIN_ALL,
    HELP_PRODUCTION_ONLY,
    HELP_REGISTRY_TYPE,
    HELP_REWRITE_VERSIONS,
    HELP_SCHEMA_VERSION,
    HELP_SECURITY_ONLY,
    HELP_TEXT,
)
from ossiq.settings import Settings
from ossiq.timeutil import cutoff_datetime_from_iso_date
from ossiq.ui.system import show_settings

app = typer.Typer()
console = Console()

helpers_app = typer.Typer(name="helpers", help="Package manager helper utilities")
helpers_app.add_typer(npm_helpers_app, name="npm")
helpers_app.add_typer(uv_helpers_app, name="uv")
app.add_typer(helpers_app, name="helpers")


def version_callback(value: bool):
    """
    Extract package version from metadata
    """

    if value:
        version = importlib.metadata.version("ossiq")
        print(f"ossiq version: {version}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
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
    ] = str(Path.home() / ".ossiq_cache.sqlite3"),
    cache_ttl: Annotated[
        int,
        typer.Option("--cache-ttl", envvar=f"{Settings.ENV_PREFIX}CACHE_TTL", help=ARGS_HELP_CACHE_TTL),
    ] = 24,
    no_cache: Annotated[
        bool,
        typer.Option("--no-cache", is_flag=True, help="Disable persistent HTTP cache for this run."),
    ] = False,
    cutoff_date: Annotated[
        str | None,
        typer.Option(
            "--cutoff-date",
            "-C",
            envvar=f"{Settings.ENV_PREFIX}CUTOFF_DATE",
            help=ARGS_HELP_CUTOFF_DATE,
        ),
    ] = None,
    cooldown_period: Annotated[
        int | None,
        typer.Option(
            "--cooldown-period",
            envvar=f"{Settings.ENV_PREFIX}COOLDOWN_PERIOD",
            help=ARGS_HELP_COOLDOWN_PERIOD,
        ),
    ] = None,
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
        "cache_destination": cache_destination,
        "cache_ttl": cache_ttl,
        "cutoff_date": cutoff_datetime_from_iso_date(cutoff_date) if cutoff_date else None,
        "cooldown_period": cooldown_period,
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

    if not no_cache:
        install_requests_cache(settings.cache_destination, settings.cache_ttl)

    if context.invoked_subcommand is None:
        command_status(ctx=context, options=CommandStatusOptions(project_path="."))


@app.command()
def help():  # pylint: disable=redefined-builtin
    """Console script for ossiq-cli."""
    console.print(HELP_TEXT)


@app.command()
def status(
    context: typer.Context,
    project_path: Annotated[str, typer.Argument()] = ".",
    lag_threshold_days: Annotated[str, typer.Option("--lag-threshold-delta", "-l", help=HELP_LAG_THRESHOULD)] = "1y",
    production: Annotated[bool, typer.Option("--production", help=HELP_PRODUCTION_ONLY)] = False,
    allow_prerelease: Annotated[
        bool, typer.Option("--allow-prerelease", help="Include pre-release versions in drift calculations")
    ] = False,
    allow_prerelease_package: Annotated[
        list[str] | None,
        typer.Option("--allow-prerelease-package", help="Allow pre-release for a specific package (repeatable)"),
    ] = None,
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
    security: Annotated[
        bool,
        typer.Option(
            "--security",
            is_flag=True,
            help="Narrow transitive recommendations to CVE-carrying packages only",
        ),
    ] = False,
    ignore: Annotated[
        list[str] | None,
        typer.Option("--ignore", "-i", help=HELP_IGNORE_PACKAGE),
    ] = None,
):
    """
    Show dependency health: drift, CVEs, and solver recommendations.
    """
    if registry_type and registry_type.lower() not in ["npm", "pypi"]:
        raise typer.BadParameter("Only `npm` and `pypi` allowed")

    command_status(
        ctx=context,
        options=CommandStatusOptions(
            project_path=project_path,
            lag_threshold_days=lag_threshold_days,
            production=production,
            allow_prerelease=allow_prerelease,
            allow_prerelease_packages=tuple(allow_prerelease_package or []),
            registry_type=registry_type,
            presentation=presentation,
            output_destination=output,
            security_only=security,
            ignore_packages=tuple(ignore or []),
        ),
    )


@app.command()
def export(
    context: typer.Context,
    project_path: Annotated[str, typer.Argument()] = ".",
    registry_type: Annotated[
        Literal["npm", "pypi"] | None, typer.Option("--registry-type", "-r", help=HELP_REGISTRY_TYPE)
    ] = None,
    allow_prerelease: Annotated[
        bool, typer.Option("--allow-prerelease", help="Include pre-release versions in drift calculations")
    ] = False,
    allow_prerelease_package: Annotated[
        list[str] | None,
        typer.Option("--allow-prerelease-package", help="Allow pre-release for a specific package (repeatable)"),
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
        Literal["1.0", "1.1", "1.2", "1.3", "1.4"] | None,
        typer.Option("--schema-version", "-s", envvar=f"{Settings.ENV_PREFIX}SCHEMA_VERSION", help=HELP_SCHEMA_VERSION),
    ] = None,
    ignore: Annotated[
        list[str] | None,
        typer.Option("--ignore", "-i", help=HELP_IGNORE_PACKAGE),
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
            allow_prerelease=allow_prerelease,
            allow_prerelease_packages=tuple(allow_prerelease_package or []),
            ignore_packages=tuple(ignore or []),
        ),
    )


@app.command()
def info(
    context: typer.Context,
    package_name: Annotated[str, typer.Argument(help=HELP_PACKAGE_NAME)],
    project_path: Annotated[str, typer.Argument()] = ".",
    registry_type: Annotated[
        Literal["npm", "pypi"] | None,
        typer.Option("--registry-type", "-r", help=HELP_REGISTRY_TYPE),
    ] = None,
    allow_prerelease: Annotated[
        bool, typer.Option("--allow-prerelease", help="Include pre-release versions in drift calculations")
    ] = False,
    allow_prerelease_package: Annotated[
        list[str] | None,
        typer.Option("--allow-prerelease-package", help="Allow pre-release for a specific package (repeatable)"),
    ] = None,
    ignore: Annotated[
        list[str] | None,
        typer.Option("--ignore", "-i", help=HELP_IGNORE_PACKAGE),
    ] = None,
):
    """
    Deep-dive into a single package: drift status, CVEs, and transitive vulnerabilities.
    """
    if registry_type and registry_type.lower() not in ["npm", "pypi"]:
        raise typer.BadParameter("Only `npm` and `pypi` allowed")

    command_info(
        ctx=context,
        options=CommandInfoOptions(
            project_path=project_path,
            package_name=package_name,
            registry_type=registry_type,
            allow_prerelease=allow_prerelease,
            allow_prerelease_packages=tuple(allow_prerelease_package or []),
            ignore_packages=tuple(ignore or []),
        ),
    )


@app.command()
def plan(
    context: typer.Context,
    project_path: Annotated[str, typer.Argument()] = ".",
    registry_type: Annotated[
        Literal["npm", "pypi"] | None,
        typer.Option("--registry-type", "-r", help=HELP_REGISTRY_TYPE),
    ] = None,
    allow_prerelease: Annotated[
        bool, typer.Option("--allow-prerelease", help="Include pre-release versions in drift calculations")
    ] = False,
    allow_prerelease_package: Annotated[
        list[str] | None,
        typer.Option("--allow-prerelease-package", help="Allow pre-release for a specific package (repeatable)"),
    ] = None,
    production: Annotated[bool, typer.Option("--production", help=HELP_PRODUCTION_ONLY)] = False,
    security: Annotated[
        bool,
        typer.Option("--security", is_flag=True, help=HELP_SECURITY_ONLY),
    ] = False,
    ignore: Annotated[list[str] | None, typer.Option("--ignore", "-i", help=HELP_IGNORE_PACKAGE)] = None,
    pin_all: Annotated[
        bool,
        typer.Option("--pin-all", is_flag=True, help=HELP_PIN_ALL),
    ] = False,
    rewrite_versions: Annotated[
        bool,
        typer.Option("--rewrite-versions", is_flag=True, help=HELP_REWRITE_VERSIONS),
    ] = False,
    override: Annotated[
        list[str] | None,
        typer.Option("--override", help=HELP_OVERRIDE_PACKAGE),
    ] = None,
    script: Annotated[
        bool,
        typer.Option("--script", is_flag=True, help="Emit the bash update script instead of the plan table"),
    ] = False,
):
    """Show what would change, or emit the bash script with --script."""
    if registry_type and registry_type.lower() not in ["npm", "pypi"]:
        raise typer.BadParameter("Only `npm` and `pypi` allowed")

    overrides = parse_override_specs(override)
    check_override_ignore_conflict(overrides, tuple(ignore or []))

    command_plan(
        ctx=context,
        options=CommandPlanOptions(
            project_path=project_path,
            registry_type=registry_type,
            allow_prerelease=allow_prerelease,
            allow_prerelease_packages=tuple(allow_prerelease_package or []),
            production=production,
            security_only=security,
            ignore_packages=tuple(ignore or []),
            pin_all=pin_all,
            rewrite_versions=rewrite_versions,
            overrides=overrides,
        ),
        script=script,
    )


@app.command()
def apply(
    context: typer.Context,
    project_path: Annotated[str, typer.Argument()] = ".",
    registry_type: Annotated[
        Literal["npm", "pypi"] | None,
        typer.Option("--registry-type", "-r", help=HELP_REGISTRY_TYPE),
    ] = None,
    allow_prerelease: Annotated[
        bool, typer.Option("--allow-prerelease", help="Include pre-release versions in drift calculations")
    ] = False,
    allow_prerelease_package: Annotated[
        list[str] | None,
        typer.Option("--allow-prerelease-package", help="Allow pre-release for a specific package (repeatable)"),
    ] = None,
    production: Annotated[bool, typer.Option("--production", help=HELP_PRODUCTION_ONLY)] = False,
    security: Annotated[
        bool,
        typer.Option("--security", is_flag=True, help=HELP_SECURITY_ONLY),
    ] = False,
    ignore: Annotated[list[str] | None, typer.Option("--ignore", "-i", help=HELP_IGNORE_PACKAGE)] = None,
    pin_all: Annotated[
        bool,
        typer.Option("--pin-all", is_flag=True, help=HELP_PIN_ALL),
    ] = False,
    rewrite_versions: Annotated[
        bool,
        typer.Option("--rewrite-versions", is_flag=True, help=HELP_REWRITE_VERSIONS),
    ] = False,
    override: Annotated[
        list[str] | None,
        typer.Option("--override", help=HELP_OVERRIDE_PACKAGE),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", is_flag=True, help="Skip confirmation prompt (for CI)"),
    ] = False,
):
    """Apply solver-recommended updates; shows the plan first, then confirms before executing."""
    if registry_type and registry_type.lower() not in ["npm", "pypi"]:
        raise typer.BadParameter("Only `npm` and `pypi` allowed")

    overrides = parse_override_specs(override)
    check_override_ignore_conflict(overrides, tuple(ignore or []))

    command_apply(
        ctx=context,
        options=CommandPlanOptions(
            project_path=project_path,
            registry_type=registry_type,
            allow_prerelease=allow_prerelease,
            allow_prerelease_packages=tuple(allow_prerelease_package or []),
            production=production,
            security_only=security,
            ignore_packages=tuple(ignore or []),
            pin_all=pin_all,
            rewrite_versions=rewrite_versions,
            overrides=overrides,
        ),
        yes=yes,
    )


if __name__ == "__main__":
    app()
