"""
Project packages overview command
"""

from dataclasses import dataclass

import typer

from ossiq import timeutil
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.presentation.system import show_operation_progress, show_settings
from ossiq.presentation.views import Command, get_presentation_view
from ossiq.service import project
from ossiq.settings import Settings
from ossiq.unit_of_work import uow_project


@dataclass(frozen=True)
class CommandOverviewOptions:
    project_path: str
    lag_threshold_days: str
    production: bool
    registry_type: str | None


def commnad_overview(ctx: typer.Context, options: CommandOverviewOptions):
    """
    Project overview command.
    """
    settings: Settings = ctx.obj
    threshold_parsed = timeutil.parse_relative_time_delta(options.lag_threshold_days)
    registry_type_map = {
        "npm": ProjectPackagesRegistry.NPM,
        "pypi": ProjectPackagesRegistry.PYPI,
    }
    show_settings(
        ctx,
        "Overview Settings",
        {
            "project_path": options.project_path,
            "lag_threshold_days": f"{threshold_parsed.days} days",
            "production": options.production,
            "narrow_registry_type": registry_type_map.get(options.registry_type),
        },
    )

    uow = uow_project.ProjectUnitOfWork(
        settings=settings,
        project_path=options.project_path,
        # FIXME: add parameter to pass narrow_package_manager for cases
        # where more than one project per directory
        production=options.production,
        narrow_package_registry=registry_type_map.get(options.registry_type),
    )

    with show_operation_progress(settings, "Collecting project packages data...") as progress:
        with progress():
            project_overview = project.overview(uow)

    # FIXME: use similar pattern to UoW to "commit" output on exit
    presentation_view = get_presentation_view(Command.OVERVIEW, settings.presentation)

    presentation_view(
        project_overview,
        threshold_parsed.days,
        destination=settings.output_destination,
    )

    # FIXME: both implementation and location below doens't feel right.
    # Potentially, could be refactored to use event-based design pattern
    # similar to email sending pattern from CosmicPython.com
    # /FIXME

    # NOTE: Check for outdated packages and exit with non-zero exit code if there
    # are any over specified threshold.
    # for pkg in project_overview.production_packages:
    #     if pkg.time_lag_days and pkg.time_lag_days > threshold_parsed.days:
    #         if settings.verbose is True:
    #             show_error(ctx, ERROR_EXIT_OUTDATED_PACKAGES)
    #         sys.exit(1)
