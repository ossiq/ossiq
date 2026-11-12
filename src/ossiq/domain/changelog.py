"""A range changelog as changelog IQ serves it (UCS v1), reduced to what an upgrade step needs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ChangelogStatus(StrEnum):
    """Whether a changelog arrived, and if not why, so a renderer can say so instead of going quiet."""

    OK = "ok"
    PENDING = "pending"
    """Still being generated when the wait budget ran out."""
    NOT_FOUND = "not_found"
    RANGE_TOO_WIDE = "range_too_wide"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ChangelogItem:
    version: str
    category: str
    """Added, Changed, Deprecated, Removed, Fixed or Security."""
    text: str
    breaking: bool
    references: tuple[str, ...] = ()
    """Issue and pull-request links the upstream text cited."""


@dataclass(frozen=True)
class MigrationGuide:
    version: str
    title: str
    url: str


@dataclass(frozen=True)
class RangeChangelog:
    status: ChangelogStatus
    source_url: str
    web_url: str
    detail: str | None = None
    """Why the status is not OK."""
    risk_level: str | None = None
    breaking_change: bool = False
    security_fix: bool = False
    cve_references: tuple[str, ...] = ()
    items: tuple[ChangelogItem, ...] = ()
    guides: tuple[MigrationGuide, ...] = ()
    markdown: str = ""

    @property
    def breaking_items(self) -> tuple[ChangelogItem, ...]:
        return tuple(item for item in self.items if item.breaking)
