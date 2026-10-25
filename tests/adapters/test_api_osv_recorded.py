"""Real api.osv.dev advisories, parsed by CveApiOsv and judged by cve_affects_version.

Kept out of test_api_osv.py so a rewrite of the adapter and its unit tests together still turns
these red.
"""

from unittest.mock import MagicMock

import pytest

from ossiq.adapters.api_osv import CveApiOsv
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.cve import CVE
from ossiq.domain.package import Package
from ossiq.solver.version_matchers import cve_affects_version

# Trimmed from api.osv.dev as of 2026-10-25. npm records publish ranges only, never `versions`.
AXIOS_GHSA = {
    "id": "GHSA-jr5f-v2jv-69x6",
    "aliases": ["CVE-2025-27152"],
    "summary": "axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "axios"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.8.2"}]}],
        },
        {
            "package": {"ecosystem": "npm", "name": "axios"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.30.0"}]}],
        },
    ],
}
# OSV spells the name in PEP 503 form; the PyPI adapter keeps the registry's display name, Jinja2.
JINJA2_GHSA = {
    "id": "GHSA-h5c8-rqwp-cp95",
    "aliases": ["CVE-2024-22195", "PYSEC-2026-1473"],
    "summary": "Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "jinja2"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}],
            "versions": ["3.1.0", "3.1.1", "3.1.2"],
        }
    ],
}


def parse(record: dict, name: str, registry: ProjectPackagesRegistry, version: str) -> CVE:
    """Parse *record* for package *name*, built the way the registry adapters build it."""
    package = Package(
        registry=registry, name=name, canonical_name=name, latest_version=version, next_version=None, repo_url=None
    )
    (cve,) = CveApiOsv(MagicMock()).parse_cve_response([record], package, version)
    return cve


@pytest.mark.parametrize(
    ("version", "affected"),
    [("0.29.0", True), ("0.30.0", False), ("1.7.3", True), ("1.8.1", True), ("1.8.2", False)],
)
def test_axios_releases_before_each_fix_are_affected(version: str, affected: bool) -> None:
    cve = parse(AXIOS_GHSA, "axios", ProjectPackagesRegistry.NPM, version)

    assert cve_affects_version(cve, version) is affected


def test_axios_names_both_fixes() -> None:
    cve = parse(AXIOS_GHSA, "axios", ProjectPackagesRegistry.NPM, "1.8.1")

    assert cve.fix_versions == ("1.8.2", "0.30.0")
    assert cve.fix_available


def test_jinja2_fix_survives_the_registry_display_name() -> None:
    cve = parse(JINJA2_GHSA, "Jinja2", ProjectPackagesRegistry.PYPI, "3.1.2")

    assert cve.fix_versions == ("3.1.3",)
    assert cve.fix_available
    assert cve_affects_version(cve, "3.1.2")
    assert not cve_affects_version(cve, "3.1.3")
