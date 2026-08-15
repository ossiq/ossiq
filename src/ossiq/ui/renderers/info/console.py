"""Console renderer for the info (package deep-dive) command."""

from collections.abc import Iterator

from rich.console import Console, RenderableType
from rich.rule import Rule

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.package import PackageDetailResult
from ossiq.settings import Settings
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.info.blocks import (
    collect_licenses,
    dependency_tree,
    drift_status,
    header,
    health_metrics,
    licenses_block,
    peer_requirements,
    policy_compliance,
    prospective_header,
    recommendation_rationale,
    security_advisories,
    transitive_cves,
    unique_cves,
    warnings_panel,
)


def installed_blocks(data: PackageDetailResult) -> Iterator[RenderableType]:
    """Output order for a package that is present in the project."""
    yield header(data.records)
    if data.warnings:
        yield warnings_panel(data.warnings)
    if data.insight:
        yield health_metrics(data.insight, data.records)

    for index, record in enumerate(data.records, start=1):
        if len(data.records) > 1:
            yield Rule(f"Occurrence {index} of {len(data.records)}", align="left")
        yield drift_status(record)
        yield dependency_tree(record)
        yield policy_compliance(record)
        if record.recommended_version:
            reason = record.recommended_version_reason
            age_days = reason.age_days if reason else None
            yield recommendation_rationale(record.recommended_version, reason, age_days)
        if record.peer_requirements:
            yield peer_requirements(record)

    yield security_advisories(unique_cves(data.records))
    if data.transitive_cve_groups:
        yield transitive_cves(data.transitive_cve_groups)

    licenses = collect_licenses(data.records)
    if len(licenses) > 1:
        yield licenses_block(licenses)


def prospective_blocks(data: PackageDetailResult) -> Iterator[RenderableType]:
    """Output order for a package that is not installed in the project."""
    yield prospective_header(data)
    if data.warnings:
        yield warnings_panel(data.warnings)
    if data.insight:
        yield health_metrics(data.insight)
        if data.insight.recommended_version:
            yield recommendation_rationale(
                data.insight.recommended_version,
                data.prospective_reason,
                data.insight.recommended_version_age_days,
            )
    yield security_advisories(data.prospective_cves)


class ConsoleInfoRenderer(AbstractUserInterfaceRenderer):
    """Console renderer for the info and add commands."""

    command = Command.INFO
    user_interface_type = UserInterfaceType.CONSOLE

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.console = Console()

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        return command in (Command.INFO, Command.ADD) and user_interface_type == UserInterfaceType.CONSOLE

    def render(self, data: PackageDetailResult, **kwargs) -> None:
        """Render single-package deep-dive to console, one blank line between blocks."""
        blocks = prospective_blocks(data) if data.is_prospective else installed_blocks(data)
        self.console.print()
        for block in blocks:
            self.console.print(block)
            self.console.print()
