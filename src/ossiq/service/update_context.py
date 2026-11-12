"""Single-package version diff, assembled once for both front doors.

`ossiq update-context` and the MCP `ossiq_evaluate_update_context` tool answer the same question:
what changes between a package's installed version and an arbitrary target. Both used to own a
copy of this orchestration — and had already diverged, building `ProjectSources` two different
ways. Architecture rule 6: anything reachable from both front doors belongs here.
"""

from typing import Any

from ossiq.service.agent import build_update_context
from ossiq.service.package import build_installed_detail, fetch_prospective_detail, matches
from ossiq.service.project.models import ScanResult
from ossiq.service.project.scan import scan
from ossiq.settings import Settings
from ossiq.sources import project_sources
from ossiq.sources.project_sources import ProjectSources


def build_update_context_payload(
    settings: Settings,
    *,
    project_path: str,
    package_name: str,
    target_version: str | None = None,
    registry_type: str | None = None,
    allow_prerelease: bool = False,
) -> dict[str, Any]:
    """Diff *package_name*'s installed (or prospective) version against *target_version*.

    Args:
        settings: Run settings.
        project_path: The project to scan.
        package_name: The package to diff, matched by alias or canonical name.
        target_version: The version to diff against; falls back to OSS IQ's own recommendation.
        registry_type: "npm" or "pypi" to narrow the scan, or None to auto-detect.
        allow_prerelease: Whether prereleases are eligible.

    Returns:
        The payload both front doors render verbatim — module-system/API breaks, engine
        compatibility, and the structural rejections along the way.
    """
    sources = project_sources.build_project_sources(
        settings,
        project_path,
        production=False,
        allow_prerelease=allow_prerelease,
        allow_prerelease_packages=(),
        registry_type=registry_type,
    )
    return update_context_from_scan(sources, scan(sources), package_name, target_version)


def update_context_from_scan(
    sources: ProjectSources,
    scan_result: ScanResult,
    package_name: str,
    target_version: str | None = None,
) -> dict[str, Any]:
    """The `build_update_context_payload` diff for a project that is already scanned.

    Args:
        sources: The live sources the scan ran on.
        scan_result: The scan to read the installed package from.
        package_name: The package to diff, matched by alias or canonical name.
        target_version: The version to diff against; falls back to OSS IQ's own recommendation.

    Returns:
        The same payload `build_update_context_payload` returns.
    """
    all_records = scan_result.production_packages + scan_result.optional_packages + scan_result.transitive_packages
    matched = [record for record in all_records if matches(record, package_name)]
    detail = (
        build_installed_detail(matched, scan_result, package_name, sources, sources.settings)
        if matched
        else fetch_prospective_detail(package_name, sources, sources.settings)
    )

    canonical_name = detail.records[0].package_name if detail.records else (detail.prospective_name or package_name)

    return build_update_context(
        detail,
        target_version=target_version,
        releases=list(sources.packages_registry.package_versions(canonical_name)),
        registry=sources.packages_registry,
        engine_context=scan_result.engine_context,
        project_declares_esm=scan_result.declares_esm,
        package_manager=scan_result.package_manager,
        package_manager_version=scan_result.package_manager_version,
    )
