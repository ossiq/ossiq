"""
Project packages overview command
"""
import sys
import typer

from rich.console import Console

from update_burden.domain.common import identify_project_registry_kind
from update_burden.presentation.system import show_error, show_settings
from update_burden.presentation.views import (
    Command,
    PresentationType,
    get_presentation_view
)
from update_burden.unit_of_work import uow_project
from update_burden import timeutil
from update_burden.service import project
from update_burden.messages import ERROR_EXIT_OUTDATED_PACKAGES

console = Console()


def commnad_overview(
        ctx: typer.Context,
        project_path: str,
        lag_threshold_days: str,
        production: bool):
    """
    Project overview command.
    """

    threshold_parsed = timeutil.parse_relative_time_delta(lag_threshold_days)

    show_settings(ctx, "Overview Settings", {
        "project_path": project_path,
        "lag_threshold_days": threshold_parsed.days,
        "production": production
    })

    packages_registry_type = identify_project_registry_kind(project_path)
    uow = uow_project.ProjectUnitOfWork(
        settings=ctx["settings"],
        project_path=project_path,
        packages_registry_type=packages_registry_type,
        production=production
    )

    if ctx["settings"].verbose is False:
        with console.status("[bold cyan]Collecting project packages data..."):
            project_overview = project.overview(uow)
    else:
        project_overview = project.overview(uow)

    presentation_view = get_presentation_view(
        Command.OVERVIEW, PresentationType.CONSOLE)
    presentation_view(project_overview, threshold_parsed.days)

    for pkg in project_overview.installed_packages_overview:
        if pkg.lag_days > threshold_parsed.days:
            if ctx["settings"].verbose is True:
                show_error(ctx, ERROR_EXIT_OUTDATED_PACKAGES)
            sys.exit(1)
