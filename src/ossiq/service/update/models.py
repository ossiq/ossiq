"""Value types of an update plan: its entries and the plan itself."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ossiq.strategy.pyramid import DEFAULT_STRATEGY, UpdateStrategy


@dataclass(frozen=True)
class PlanOptions:
    """What `plan`, `apply` and `upgrade` build a plan from; an upgrade session keeps it to re-plan alike."""

    project_path: str
    registry_type: Literal["npm", "pypi"] | None = None
    allow_prerelease: bool = False
    allow_prerelease_packages: tuple[str, ...] = ()
    production: bool = False
    update_strategy: UpdateStrategy = DEFAULT_STRATEGY
    strategy_overrides: tuple[tuple[str, UpdateStrategy], ...] = ()
    ignore_packages: tuple[str, ...] = ()
    pin_all: bool = False
    rewrite_versions: bool = False
    overrides: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    allow_partial: bool = False
