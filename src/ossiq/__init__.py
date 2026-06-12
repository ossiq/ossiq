"""ossiq — dependency health and security scanner."""

from ossiq.domain.cve import CVE
from ossiq.domain.package import Package
from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ScanRecord, ScanResult, scan
from ossiq.settings import Settings
from ossiq.unit_of_work import core as unit_of_work

__all__ = [
    "scan",
    "ScanResult",
    "ScanRecord",
    "Settings",
    "CVE",
    "Package",
    "VersionsDifference",
    "unit_of_work",
]

__author__ = "Maksym Klymyshyn"
__email__ = "klymyshyn@gmail.com"
