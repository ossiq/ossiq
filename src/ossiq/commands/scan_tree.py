"""
Project packages scan command
"""

import typer

from ossiq import timeutil
from ossiq.commands.scan import CommandScanOptions
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.service import dependency, project
from ossiq.settings import Settings
from ossiq.ui.system import show_operation_progress, show_settings
from ossiq.unit_of_work import uow_project


def command_scan_tree(ctx: typer.Context, options: CommandScanOptions):
    """
    Project scan command.
    """
    settings: Settings = ctx.obj
    threshold_parsed = timeutil.parse_relative_time_delta(options.lag_threshold_days)
    registry_type_map = {
        "npm": ProjectPackagesRegistry.NPM,
        "pypi": ProjectPackagesRegistry.PYPI,
    }

    show_settings(
        ctx,
        "Scan Settings",
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
        production=options.production,
        narrow_package_registry=registry_type_map.get(options.registry_type),
    )

    with show_operation_progress(settings, "Collecting project packages data...") as progress:
        with progress():
            project_scan = project.scan(uow)

    with show_operation_progress(settings, "Scanning transitive dependencies...") as progress:
        with progress():
            tree = dependency.traverse_tree(uow, project_scan)

    import pprint

    pprint.pprint(tree)
