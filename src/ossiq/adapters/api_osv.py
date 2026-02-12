import requests

from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package

from .api_interfaces import AbstractCveDatabaseApi

ECOSYSTEM_MAPPING = {ProjectPackagesRegistry.NPM: "npm", ProjectPackagesRegistry.PYPI: "PyPI"}


class CveApiOsv(AbstractCveDatabaseApi):
    """
    An AbstractCveApi implementation for osv.dev CVEs repository
    """

    def __init__(self):
        self.base_url = "https://api.osv.dev/v1"

    def __repr__(self):
        return f"OsvApiClient(base_url='{self.base_url}')"

    def get_cves_for_package(self, package: Package, version: str) -> set[CVE]:
        payload = {
            "package": {"name": package.name, "ecosystem": ECOSYSTEM_MAPPING[package.registry]},
            "version": version,
        }

        resp = requests.post(f"{self.base_url}/query", json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        vulnerabilities_raw = data.get("vulns", [])

        cves = set()
        for cve_raw in vulnerabilities_raw:
            cves.add(
                CVE(
                    id=cve_raw["id"],
                    cve_ids=tuple(cve_raw.get("aliases", [])),
                    source=CveDatabase.OSV,
                    package_name=package.name,
                    package_registry=package.registry,
                    summary=cve_raw.get("summary", ""),
                    severity=self._map_severity(cve_raw.get("severity", [])),
                    affected_versions=tuple(self._extract_affected_versions(cve_raw)),
                    published=cve_raw.get("published"),
                    link=self._build_osv_link(cve_raw["id"]),
                )
            )
        return cves

    def _map_severity(self, osv_severity: list[dict]) -> Severity:
        """
        The purpose is to map osv.dev score numbers to simplified
        severity levels.

        :param self: Description
        :param osv_severity: Description
        :type osv_severity: List[dict]
        :return: Description
        :rtype: Severity
        """
        if not osv_severity:
            return Severity.MEDIUM  # fallback

        scores = []
        for s in osv_severity:
            try:
                scores.append(float(s.get("score", 0)))
            except (ValueError, TypeError):
                pass

        if not scores:
            return Severity.MEDIUM

        max_score = max(scores)

        if max_score >= 9.0:
            return Severity.CRITICAL
        if max_score >= 7.0:
            return Severity.HIGH
        if max_score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    def _extract_affected_versions(self, osv_entry: dict) -> list[str]:
        """
        OSV provides ranges, but also `versions` which is easier: explicit versions.
        """
        versions = []
        for aff in osv_entry.get("affected", []):
            versions.extend(aff.get("versions", []))
        return versions

    def _build_osv_link(self, osv_id: str) -> str:
        return f"https://osv.dev/{osv_id}"
