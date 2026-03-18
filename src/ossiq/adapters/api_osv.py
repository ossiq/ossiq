from ossiq.clients.osv import OsvSession
from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package

from .api_interfaces import AbstractCveDatabaseApi

ECOSYSTEM_MAPPING = {ProjectPackagesRegistry.NPM: "npm", ProjectPackagesRegistry.PYPI: "PyPI"}


class CveApiOsv(AbstractCveDatabaseApi):
    """
    An AbstractCveDatabaseApi implementation for osv.dev CVEs repository.
    Uses the /v1/querybatch endpoint to fetch CVEs for all packages in a single request.
    """

    def __init__(self, session: OsvSession):
        self.base_url = "https://api.osv.dev/v1"
        self.session = session

    def __repr__(self):
        return f"CveApiOsv(base_url='{self.base_url}')"

    def get_cves_batch(self, packages_with_versions: list[tuple[Package, str]]) -> dict[tuple[str, str], set[CVE]]:
        if not packages_with_versions:
            return {}

        queries = [
            {"package": {"name": pkg.name, "ecosystem": ECOSYSTEM_MAPPING[pkg.registry]}, "version": version}
            for pkg, version in packages_with_versions
        ]

        resp = self.session.post(f"{self.base_url}/querybatch", json={"queries": queries}, timeout=30)
        resp.raise_for_status()

        results: dict[tuple[str, str], set[CVE]] = {}
        for (pkg, version), result in zip(packages_with_versions, resp.json().get("results", []), strict=True):
            cves = self._parse_cves_from_result(result, pkg)

            # Handle pagination (triggers when a single package exceeds ~1000 CVEs — extremely rare)
            page_token = result.get("next_page_token")
            while page_token:
                page_resp = self.session.post(
                    f"{self.base_url}/querybatch",
                    json={
                        "queries": [
                            {
                                "package": {"name": pkg.name, "ecosystem": ECOSYSTEM_MAPPING[pkg.registry]},
                                "version": version,
                                "page_token": page_token,
                            }
                        ]
                    },
                    timeout=30,
                )
                page_resp.raise_for_status()
                page_result = page_resp.json().get("results", [{}])[0]
                cves |= self._parse_cves_from_result(page_result, pkg)
                page_token = page_result.get("next_page_token")

            results[(pkg.name, version)] = cves

        return results

    def _parse_cves_from_result(self, result: dict, package: Package) -> set[CVE]:
        cves = set()
        for cve_raw in result.get("vulns", []):
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
