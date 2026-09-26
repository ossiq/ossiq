import requests

from ossiq.clients.batch import BatchClient
from ossiq.clients.client_osv import ECOSYSTEM_MAPPING, OsvBatchStrategy, OsvDetailsBatchStrategy
from ossiq.clients.common import get_user_agent
from ossiq.domain.common import CveDatabase, SourceFetch, combine_statuses
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package
from ossiq.risk.cvss import parse_cvss_base_score
from ossiq.settings import Settings

SUMMARY_MAX_CHARS = 200


def advisory_summary(cve_raw: dict) -> str:
    """Return the advisory's one-line summary, falling back to the first line of `details`.

    PYSEC records routinely omit `summary` and carry the whole text in `details`, so reading only
    `summary` left those CVEs with nothing to show.
    """
    summary = (cve_raw.get("summary") or "").strip()
    if summary:
        return summary
    details = (cve_raw.get("details") or "").strip()
    first_line = details.splitlines()[0].strip() if details else ""
    if len(first_line) <= SUMMARY_MAX_CHARS:
        return first_line
    return f"{first_line[: SUMMARY_MAX_CHARS - 1].rstrip()}…"


class CveApiOsv:
    """
    CVE client for osv.dev.
    Discovers vulnerability IDs via /v1/querybatch, then fetches full records
    from /v1/vulns/{id}.
    """

    session: requests.Session

    def __init__(self, settings: Settings):

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": get_user_agent()})

        self._strategy = OsvBatchStrategy(self.session)
        self._batch_client = BatchClient(self._strategy)
        self._details_batch_client = BatchClient(OsvDetailsBatchStrategy(self.session))

    def __repr__(self):
        return f"CveApiOsv(base_url='{self._strategy.BASE_URL}')"

    def get_cves_batch(
        self, packages_with_versions: list[tuple[Package, str]]
    ) -> SourceFetch[dict[tuple[str, str], set[CVE]]]:
        """Discover vulnerability IDs for each (package, version), then fetch their full records.

        Args:
            packages_with_versions: The exact pairs to query.

        Returns:
            The CVE map, and whether OSV actually delivered it. A failure fetching *details*
            counts against the status too, not just a failure discovering IDs: real vulnerability
            IDs that could not be fully described are still missing data.
        """
        if not packages_with_versions:
            return SourceFetch({})

        pkg_map: dict[tuple[str, str], Package] = {(pkg.name, version): pkg for pkg, version in packages_with_versions}
        merged: dict[tuple[str, str], list[dict]] = {}
        for chunk_data in self._batch_client.run_batch(packages_with_versions):
            for key, vulns in chunk_data.items():
                merged.setdefault(key, []).extend(vulns)
        statuses = [self._batch_client.last_summary.status]

        vulnerability_ids = sorted({vuln["id"] for vulns in merged.values() for vuln in vulns})
        details: dict[str, dict] = {}
        if vulnerability_ids:
            for chunk_data in self._details_batch_client.run_batch(vulnerability_ids):
                details.update(chunk_data)
            statuses.append(self._details_batch_client.last_summary.status)

        return SourceFetch(
            {
                (pkg.name, version): self.parse_cve_response(
                    [details.get(vuln["id"], vuln) for vuln in merged.get((pkg.name, version), [])],
                    pkg_map[(pkg.name, version)],
                    version,
                )
                for pkg, version in packages_with_versions
            },
            combine_statuses(statuses),
        )

    def parse_cve_response(self, raw_vulns: list[dict], package: Package, installed_version: str) -> set[CVE]:
        cves = set()
        for cve_raw in raw_vulns:
            fix_versions = self.extract_fix_versions(cve_raw, package)
            cves.add(
                CVE(
                    id=cve_raw["id"],
                    cve_ids=tuple(cve_raw.get("aliases", [])),
                    source=CveDatabase.OSV,
                    package_name=package.name,
                    package_registry=package.registry,
                    summary=advisory_summary(cve_raw),
                    severity=self.map_cve_severity(cve_raw.get("severity", [])),
                    affected_versions=tuple(self.extract_affected_versions(cve_raw)),
                    published=cve_raw.get("published"),
                    link=self.build_osv_link(cve_raw["id"]),
                    fix_versions=fix_versions,
                    fix_available=bool(fix_versions),
                )
            )
        return cves

    def map_cve_severity(self, osv_severity: list[dict]) -> Severity:
        if not osv_severity:
            return Severity.MEDIUM  # fallback

        scores = []
        for s in osv_severity:
            raw = s.get("score", "")
            try:
                # Some OSV severity types (e.g. a distro's own numeric rating) are already a
                # bare number. Most are not: CVSS_V3/CVSS_V4 entries carry a full vector string
                # ("CVSS:3.1/AV:N/AC:L/..."), which float() cannot parse - it has no numeric
                # score in it at all; the score has to be computed from the vector (N2).
                scores.append(float(raw))
                continue
            except (ValueError, TypeError):
                pass
            parsed = parse_cvss_base_score(str(raw)) if raw else None
            if parsed is not None:
                scores.append(parsed)

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

    def extract_fix_versions(self, osv_entry: dict, package: Package) -> tuple[str, ...]:
        """
        OSV advisory can contain several affected records from the same ecosystem,
        potentially for sibling packages. Including
        canonical_name also accommodates npm aliases
        """

        ecosystem = ECOSYSTEM_MAPPING[package.registry]
        package_names = {package.name, package.canonical_name}
        package_names.discard(None)

        fix_versions = []

        for affected in osv_entry.get("affected", []):
            affected_package = affected.get("package", {})

            if affected_package.get("ecosystem") != ecosystem:
                continue

            # FIXME: alias could be actually potential vector
            if affected_package.get("name") not in package_names:
                continue

            for affected_range in affected.get("ranges", []):
                for event in affected_range.get("events", []):
                    if "fixed" in event:
                        fix_versions.append(event["fixed"])

        return tuple(fix_versions)

    def extract_affected_versions(self, osv_entry: dict) -> list[str]:
        """
        OSV provides ranges, but also `versions` which is easier: explicit versions.
        """
        versions = []
        for aff in osv_entry.get("affected", []):
            versions.extend(aff.get("versions", []))
        return versions

    def build_osv_link(self, osv_id: str) -> str:
        return f"https://osv.dev/{osv_id}"
