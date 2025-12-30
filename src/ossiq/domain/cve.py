"""
CVE (Common Vulnerabilities and Exposures) is a standardized system for
identifying and cataloging publicly known cybersecurity vulnerabilities.
"""

from dataclasses import dataclass
from enum import Enum

from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


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
    # resolved versions
    affected_versions: tuple[str, ...]
    published: str | None
    # URL to upstream advisory
    link: str
