"""
Single package deep-dive command.
"""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.messages import ERROR_PACKAGE_NOT_FOUND
from ossiq.service import project
from ossiq.service.package import PackageDetailResult, TransitiveCVEGroup
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.settings import Settings
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_operation_progress
from ossiq.unit_of_work import uow_project

_SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass(frozen=True)
class CommandPackageOptions:
    project_path: str
    package_name: str
    registry_type: Literal["npm", "pypi"] | None
    allow_prerelease: bool = False
    allow_prerelease_packages: tuple[str, ...] = ()


def _matches(record: ScanRecord, package_name: str) -> bool:
    """Case-insensitive exact match on dependency_name or package_name (canonical)."""
    needle = package_name.lower()
    return (
        record.dependency_name is not None and record.dependency_name.lower() == needle
    ) or record.package_name.lower() == needle


def _collect_transitive_cve_groups(scan_result: ScanResult, package_name: str) -> list[TransitiveCVEGroup]:
    """
    Find all transitive packages downstream of `package_name`
    (i.e. `package_name` appears in their dependency_path) and have CVEs.
    Group by (name, version), sort by worst CVE severity.
    """
    acc: dict[str, TransitiveCVEGroup] = {}
    needle = package_name.lower()

    for record in scan_result.transitive_packages:
        if not record.cve:
            continue
        path = record.dependency_path or []
        if any(p.lower() == needle for p in path):
            key = f"{record.package_name}@{record.installed_version}"
            if key not in acc:
                acc[key] = TransitiveCVEGroup(
                    name=record.package_name,
                    version=record.installed_version,
                    cves=list(record.cve),
                )

    def worst_severity(group: TransitiveCVEGroup) -> int:
        return min(_SEVERITY_ORDER.get(c.severity, 99) for c in group.cves)

    return sorted(acc.values(), key=worst_severity)


def command_package(ctx: typer.Context, options: CommandPackageOptions) -> None:
    """Single package deep-dive command."""
    settings: Settings = ctx.obj
    registry_type_map = {
        "npm": ProjectPackagesRegistry.NPM,
        "pypi": ProjectPackagesRegistry.PYPI,
    }

    uow = uow_project.ProjectUnitOfWork(
        settings=settings,
        project_path=options.project_path,
        production=False,
        narrow_package_registry=registry_type_map.get(options.registry_type or ""),
        allow_prerelease=options.allow_prerelease,
        allow_prerelease_packages=options.allow_prerelease_packages,
    )

    with show_operation_progress(settings, "Collecting project packages data...") as progress:
        with progress():
            scan_result = project.scan(uow)

    all_records = scan_result.production_packages + scan_result.optional_packages + scan_result.transitive_packages
    matched = [r for r in all_records if _matches(r, options.package_name)]

    if not matched:
        typer.echo(ERROR_PACKAGE_NOT_FOUND.format(package_name=options.package_name), err=True)
        raise typer.Exit(code=1)

    detail = PackageDetailResult(
        records=matched,
        transitive_cve_groups=_collect_transitive_cve_groups(scan_result, options.package_name),
        project_name=scan_result.project_name,
        packages_registry=scan_result.packages_registry,
    )

    renderer = get_renderer(
        command=Command.PACKAGE,
        user_interface_type=UserInterfaceType.CONSOLE,
        settings=settings,
    )
    renderer.render(data=detail)
