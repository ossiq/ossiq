"""Single package deep-dive command."""

from dataclasses import dataclass
from typing import Literal

import typer
from rich.console import Console

from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.service import project
from ossiq.service.package import (
    PackageDetailResult,
    TransitiveCVEGroup,
    build_package_insight,
    evaluate_package_rules,
    fetch_prospective_detail,
)
from ossiq.service.project import ScanRecord, ScanResult, apply_recommendations
from ossiq.settings import Settings
from ossiq.solver import dependencies_solver
from ossiq.sources import project_sources
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_operation_progress, show_scan_progress

_SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass(frozen=True)
class CommandInfoOptions:
    project_path: str
    package_name: str
    registry_type: Literal["npm", "pypi"] | None
    allow_prerelease: bool = False
    allow_prerelease_packages: tuple[str, ...] = ()
    ignore_packages: tuple[str, ...] = ()


def matches(record: ScanRecord, package_name: str) -> bool:
    """Case-insensitive exact match on dependency_name or package_name (canonical)."""
    needle = package_name.lower()
    return (
        record.dependency_name is not None and record.dependency_name.lower() == needle
    ) or record.package_name.lower() == needle


def collect_transitive_cve_groups(scan_result: ScanResult, package_name: str) -> list[TransitiveCVEGroup]:
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


def build_installed_detail(
    matched: list[ScanRecord],
    scan_result: ScanResult,
    package_name: str,
    sources: project_sources.ProjectSources,
    settings: Settings,
) -> PackageDetailResult:
    """Build a PackageDetailResult for a package already installed in the project."""
    record = matched[0]
    canonical_name = record.package_name

    # Transitive packages have skip_current=True during scan, so up-to-date ones
    # never get recommended_version set. Re-run solver for them here so [03] and
    # [07] always render. Registry cache is warm — no extra HTTP calls.
    needs_solve = [r for r in matched if r.recommended_version is None]
    if needs_solve:
        solo_output = dependencies_solver.solve_transitive(
            needs_solve,
            sources.packages_registry,
            {},
            allow_prerelease=sources.allow_prerelease,
            cooldown_period=settings.cooldown_period,
        )
        apply_recommendations(needs_solve, solo_output, skip_current=False)

    # These fetches hit the already-warm in-process cache — no extra HTTP round-trips.
    package = sources.packages_registry.package_info(canonical_name)
    versions = list(sources.packages_registry.package_versions(canonical_name))
    package.downloads_recent = sources.packages_registry.fetch_downloads_recent(canonical_name)

    rec_version = record.recommended_version
    rec_age = record.recommended_version_reason.age_days if record.recommended_version_reason else None

    insight = build_package_insight(
        package=package,
        versions=versions,
        settings=settings,
        recommended_version=rec_version,
        recommended_version_age_days=rec_age,
    )
    warnings = evaluate_package_rules(insight, settings)

    return PackageDetailResult(
        records=matched,
        transitive_cve_groups=collect_transitive_cve_groups(scan_result, package_name),
        project_name=scan_result.project_name,
        packages_registry=scan_result.packages_registry,
        insight=insight,
        warnings=warnings,
    )


def command_info(ctx: typer.Context, options: CommandInfoOptions) -> None:
    """Single package deep-dive command."""
    settings: Settings = ctx.obj
    registry_type_map = {
        "npm": ProjectPackagesRegistry.NPM,
        "pypi": ProjectPackagesRegistry.PYPI,
    }

    sources = project_sources.ProjectSources(
        settings=settings,
        project_path=options.project_path,
        production=False,
        narrow_package_registry=registry_type_map.get(options.registry_type or ""),
        allow_prerelease=options.allow_prerelease,
        allow_prerelease_packages=options.allow_prerelease_packages,
        ignore_packages=options.ignore_packages,
    )

    with show_scan_progress(settings) as on_step:
        scan_result = project.scan(sources, on_step=on_step)

    if scan_result.manifest_lock_divergent:
        Console().print(
            f"[yellow]Warning:[/yellow] pyproject.toml and uv.lock are out of sync for: "
            f"[bold]{', '.join(scan_result.manifest_lock_divergent)}[/bold]. "
            "Run [bold]uv lock[/bold] to regenerate the lockfile."
        )

    all_records = scan_result.production_packages + scan_result.optional_packages + scan_result.transitive_packages
    matched = [r for r in all_records if matches(r, options.package_name)]

    if matched:
        detail = build_installed_detail(matched, scan_result, options.package_name, sources, settings)
    else:
        # Package not in this project — run the prospective flow.
        # sources.__enter__ was already called inside project.scan(), so packages_registry is live.
        with show_operation_progress(settings, f"Fetching prospective info for {options.package_name}...") as progress:
            with progress():
                detail = fetch_prospective_detail(options.package_name, sources, settings)

    renderer = get_renderer(
        command=Command.INFO,
        user_interface_type=UserInterfaceType.CONSOLE,
        settings=settings,
    )
    renderer.render(data=detail)
