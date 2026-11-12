"""Gather what a pending step's preview shows, from a scan that is already done."""

from __future__ import annotations

from collections.abc import Callable

import requests

from ossiq.clients.client_changelogiq import fetch_range_changelog
from ossiq.domain.changelog import RangeChangelog
from ossiq.service.package import build_installed_detail, matches
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.update_context import update_context_from_scan
from ossiq.service.upgrade.models import StepPackage, UpgradeStep
from ossiq.service.upgrade.view import PackagePreview, StepPreview
from ossiq.sources.project_sources import ProjectSources

ChangelogFetcher = Callable[[str, StepPackage], RangeChangelog]
"""Looks up a package's changelog from its ecosystem and the move: installed to target."""


def build_preview(
    sources: ProjectSources, scan: ScanResult, step: UpgradeStep, fetch_changelog: ChangelogFetcher | None = None
) -> StepPreview:
    """Describe each package of *step* the way `info`, `status --full` and `update-context` would.

    Args:
        sources: The live sources the scan ran on.
        scan: The scan the step was planned from.
        step: The step to describe.
        fetch_changelog: Looks up each direct package's changelog; None leaves them out.

    Returns:
        One preview per package, in the step's order.
    """
    records = scan.production_packages + scan.optional_packages + scan.transitive_packages
    ecosystem = scan.packages_registry.lower()
    previews = []
    for package in step.packages:
        matched = [r for r in records if matches(r, package.name)]
        detail = context = changelog = None
        if package.is_direct:
            if matched:
                detail = build_installed_detail(
                    matched, scan, package.name, sources, sources.settings, requested_version=package.target
                )
                context = update_context_from_scan(sources, scan, package.name, package.target)
            if fetch_changelog:
                changelog = fetch_changelog(ecosystem, package)
        previews.append(
            PackagePreview(
                package=package,
                record=installed_record(matched, package.current),
                detail=detail,
                update_context=context,
                changelog=changelog,
            )
        )
    return StepPreview(packages=tuple(previews), engine_context=scan.engine_context)


def installed_record(matched: list[ScanRecord], version: str) -> ScanRecord | None:
    """The record of the copy at *version*; the first match when no copy has it."""
    for record in matched:
        if record.installed_version == version:
            return record
    return matched[0] if matched else None


def changelog_fetcher(on_wait: Callable[[str], None] | None = None) -> ChangelogFetcher:
    """A fetcher that asks changelog IQ for installed → target, waiting while it generates the answer.

    Args:
        on_wait: Receives the API's progress text each time it asks to be asked again.
    """
    session = requests.Session()
    return lambda ecosystem, package: fetch_range_changelog(
        session, ecosystem, package.registry_name, package.current, package.target, on_wait=on_wait
    )
