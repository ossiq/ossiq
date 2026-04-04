import requests

from ossiq.clients.batch import BatchClient
from ossiq.clients.client_osv import OsvBatchStrategy
from ossiq.clients.common import get_user_agent
from ossiq.domain.common import CveDatabase
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package
from ossiq.settings import Settings

from .api_interfaces import AbstractCveDatabaseApi


class CveApiOsv(AbstractCveDatabaseApi):
    """
    An AbstractCveDatabaseApi implementation for osv.dev CVEs repository.
    Uses BatchClient + OsvBatchStrategy to chunk, retry, and rate-limit requests
    to the /v1/querybatch endpoint.

    Note, that pagination is intentionally not implemented, since batch
    sizes are relatively small (50) and limits are pretty high (more than 1K CVEs per request)
    """

    session: requests.Session

    def __init__(self, settings: Settings):

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": get_user_agent()})

        self._strategy = OsvBatchStrategy(self.session)
        self._batch_client = BatchClient(self._strategy)

    def __repr__(self):
        return f"CveApiOsv(base_url='{self._strategy.BASE_URL}')"

    def get_cves_batch(self, packages_with_versions: list[tuple[Package, str]]) -> dict[tuple[str, str], set[CVE]]:
        if not packages_with_versions:
            return {}

        pkg_map: dict[tuple[str, str], Package] = {(pkg.name, version): pkg for pkg, version in packages_with_versions}
        merged: dict[tuple[str, str], list[dict]] = {}
        for chunk_data in self._batch_client.run_batch(packages_with_versions):
            merged.update(chunk_data)

        return {
            (pkg.name, version): self._parse_cves(
                merged.get((pkg.name, version), []),
                pkg_map[(pkg.name, version)],
            )
            for pkg, version in packages_with_versions
        }

    def _parse_cves(self, raw_vulns: list[dict], package: Package) -> set[CVE]:
        cves = set()
        for cve_raw in raw_vulns:
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
