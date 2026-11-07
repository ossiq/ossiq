"""What an upgrade subcommand hands to a renderer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ossiq.domain.changelog import RangeChangelog
from ossiq.domain.common import EngineContext
from ossiq.service.package import PackageDetailResult
from ossiq.service.project.models import ScanRecord
from ossiq.service.upgrade.models import StepPackage, UpgradeSession, UpgradeStep


class Outcome(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FINISHED = "FINISHED"
    ABORTED = "ABORTED"
    NOTHING_TO_DO = "NOTHING_TO_DO"


@dataclass(frozen=True)
class PackagePreview:
    """Everything OSS IQ knows about one package's move, for the pending step's preview."""

    package: StepPackage
    record: ScanRecord | None
    """The installed copy's scan record: what `status --full` draws a row from."""
    detail: PackageDetailResult | None
    """The `info` view of the package, checked against the target version. Direct packages only."""
    update_context: dict[str, Any] | None
    """Module-system and engine breaks between installed and target, as `update-context` reports. Direct only."""
    changelog: RangeChangelog | None = None
    """What changelog IQ says changed between installed and target. Direct only; None when not fetched."""


@dataclass(frozen=True)
class StepPreview:
    packages: tuple[PackagePreview, ...]
    engine_context: EngineContext


@dataclass(frozen=True)
class UpgradeView:
    """The session after a subcommand, and what to tell the user about it."""

    outcome: Outcome
    session: UpgradeSession | None
    step: UpgradeStep | None
    preview: StepPreview | None = None
    commands: tuple[str, ...] = ()
    """The subcommands that make sense next."""
    message: str | None = None
    changelogs: tuple[tuple[StepPackage, RangeChangelog], ...] = ()
    """Set by `changelog`: the full range changelog of each direct package of the step."""
    attention: bool = False
    """The step needs the user: tests failed, the install was refused, or the target moved."""
