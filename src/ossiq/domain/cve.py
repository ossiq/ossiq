"""
CVE (Common Vulnerabilities and Exposures) is a standardized system for
identifying and cataloging publicly known cybersecurity vulnerabilities.
"""

from dataclasses import dataclass
from enum import StrEnum

from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class AffectedRange:
    """One affected interval of an advisory, as OSV's range events describe it.

    npm advisories carry only ranges - OSV never enumerates their versions - so a CVE judged by
    `affected_versions` alone read every npm release as clean. `fixed` and `last_affected` are
    mutually exclusive; both None means the interval is still open (no fix published).
    """

    # None when the range starts at OSV's "0" - every release before the upper bound
    introduced: str | None = None
    # first release outside the interval (exclusive bound)
    fixed: str | None = None
    # last release inside the interval (inclusive bound), for advisories that name no fix
    last_affected: str | None = None

    def constraint(self, registry: ProjectPackagesRegistry) -> str:
        """Render the interval in the registry's own constraint syntax.

        Args:
            registry: Picks the separator: npm joins comparators with a space, PEP 440 with a comma.

        Returns:
            e.g. ">=12.0.0 <12.0.1" on npm or ">=2.3.0,<2.31.0" on PyPI; "*" for an interval with
            no bound at all.
        """
        bounds = []
        if self.introduced is not None:
            bounds.append(f">={self.introduced}")
        if self.fixed is not None:
            bounds.append(f"<{self.fixed}")
        elif self.last_affected is not None:
            bounds.append(f"<={self.last_affected}")
        separator = "," if registry == ProjectPackagesRegistry.PYPI else " "
        return separator.join(bounds) or "*"


@dataclass(frozen=True)
class CVE:
    """
    Model to represent a CVE from various databases
    """

    # primary ID (e.g. CVE-2021-23337 or GHSA-...)
    id: str
    # all aliases (CVE, GHSA, OSV)
    cve_ids: tuple[str, ...]
    # where this record came from
    source: CveDatabase
    package_name: str
    # e.g. "npm", "pypi"
    package_registry: ProjectPackagesRegistry
    summary: str
    severity: Severity
    # versions OSV enumerates for this package; always empty for npm, which publishes only
    # ranges - judge exposure with solver.version_matchers.cve_affects_version, never with `in`
    affected_versions: tuple[str, ...]
    published: str | None
    # URL to upstream advisory
    link: str

    epss: float | None = None  # 0-1 probability or None
    fix_available: bool = False
    fix_versions: tuple[str, ...] = ()
    fix_age_days: int | None = None
    affected_ranges: tuple[AffectedRange, ...] = ()
