"""
Project packages overview command
"""
import sys
import typer

from ossiq.domain.common import identify_project_registry_kind
from ossiq.presentation.system import show_error, show_operation_progress, show_settings
from ossiq.presentation.views import (
    Command,
    get_presentation_view
)
from ossiq.settings import Settings
from ossiq.unit_of_work import uow_project
from ossiq import timeutil
from ossiq.service import project
from ossiq.messages import ERROR_EXIT_OUTDATED_PACKAGES


def commnad_overview(
        ctx: typer.Context,
        project_path: str,
        lag_threshold_days: str,
        production: bool):
    """
    Project overview command.
    """
    settings: Settings = ctx["settings"]
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

    with show_operation_progress(settings, "Collecting project packages data...") as progress:
        with progress():
            project_overview = project.overview(uow)

    # FIXME: use similar pattern to UoW to "commit" output on exit
    presentation_view = get_presentation_view(
        Command.OVERVIEW,
        ctx["settings"].presentation
    )

    presentation_view(
        project_overview,
        threshold_parsed.days,
        destination=settings.output_destination)

    # FIXME: both implementation and location below doens't feel right.
    # Potentially, could be refactored to use event-based design pattern
    # similar to email sending pattern from CosmicPython.com
    # /FIXME

    # NOTE: Check for outdated packages and exit with non-zero exit code if there
    # are any over specified threshold.
    for pkg in project_overview.production_packages:
        if pkg.time_lag_days > threshold_parsed.days:
            if ctx["settings"].verbose is True:
                show_error(ctx, ERROR_EXIT_OUTDATED_PACKAGES)
            sys.exit(1)
