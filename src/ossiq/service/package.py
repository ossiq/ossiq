"""
Data models for the single-package deep-dive service result.
"""

from dataclasses import dataclass

from ossiq.domain.cve import CVE
from ossiq.service.project import ScanRecord


@dataclass
class TransitiveCVEGroup:
    name: str
    version: str
    cves: list[CVE]


@dataclass
class PackageDetailResult:
    records: list[ScanRecord]
    transitive_cve_groups: list[TransitiveCVEGroup]
    project_name: str
    packages_registry: str
