# pylint: disable=protected-access
"""
Tests for CveApiOsv in ossiq.adapters.api_osv module.
"""

from unittest.mock import MagicMock

import pytest

from ossiq.adapters.api_osv import CveApiOsv
from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import Severity
from ossiq.domain.package import Package


def make_package(name: str, registry: ProjectPackagesRegistry = ProjectPackagesRegistry.NPM) -> Package:
    return Package(registry=registry, name=name, latest_version="1.0.0", next_version=None, repo_url=None)


def make_session(responses: list[dict]) -> MagicMock:
    """Build a mock OsvSession whose .post() returns successive responses."""
    session = MagicMock()
    mock_responses = [MagicMock(json=MagicMock(return_value=r)) for r in responses]
    session.post.side_effect = mock_responses
    return session


def make_osv_vuln(osv_id: str = "GHSA-xxxx-0001") -> dict:
    return {
        "id": osv_id,
        "aliases": ["CVE-2024-0001"],
        "summary": "A test vulnerability",
        "severity": [{"score": 7.5}],
        "affected": [{"versions": ["1.0.0", "1.1.0"]}],
        "published": "2024-01-01T00:00:00Z",
    }


class TestGetCvesBatch:
    def test_empty_input_returns_empty_dict(self):
        """Test that an empty input list returns an empty dict without making any HTTP call."""
        # Arrange
        session = MagicMock()
        api = CveApiOsv(session)

        # Act
        result = api.get_cves_batch([])

        # Assert
        assert result == {}
        session.post.assert_not_called()

    def test_returns_correct_mapping_for_single_package(self):
        """Test that a single package result is keyed by (package.name, version)."""
        # Arrange
        pkg = make_package("lodash")
        version = "4.17.20"
        session = make_session([{"results": [{"vulns": [make_osv_vuln("GHSA-xxxx-0001")]}]}])
        api = CveApiOsv(session)

        # Act
        result = api.get_cves_batch([(pkg, version)])

        # Assert
        assert ("lodash", "4.17.20") in result
        cves = result[("lodash", "4.17.20")]
        assert len(cves) == 1
        cve = next(iter(cves))
        assert cve.id == "GHSA-xxxx-0001"
        assert cve.source == CveDatabase.OSV
        assert cve.package_name == "lodash"
        assert cve.package_registry == ProjectPackagesRegistry.NPM
        assert cve.link == "https://osv.dev/GHSA-xxxx-0001"

    def test_returns_correct_mapping_for_multiple_packages(self):
        """Test that results are correctly mapped per (name, version) for multiple packages."""
        # Arrange
        pkg_a = make_package("react")
        pkg_b = make_package("express")
        session = make_session(
            [
                {
                    "results": [
                        {"vulns": [make_osv_vuln("GHSA-aaaa-0001")]},
                        {"vulns": [make_osv_vuln("GHSA-bbbb-0002"), make_osv_vuln("GHSA-bbbb-0003")]},
                    ]
                }
            ]
        )
        api = CveApiOsv(session)

        # Act
        result = api.get_cves_batch([(pkg_a, "18.0.0"), (pkg_b, "4.18.0")])

        # Assert
        assert len(result[("react", "18.0.0")]) == 1
        assert len(result[("express", "4.18.0")]) == 2

    def test_returns_empty_set_for_package_with_no_cves(self):
        """Test that a package with no vulnerabilities maps to an empty set."""
        # Arrange
        pkg = make_package("safe-package")
        session = make_session([{"results": [{"vulns": []}]}])
        api = CveApiOsv(session)

        # Act
        result = api.get_cves_batch([(pkg, "1.0.0")])

        # Assert
        assert result[("safe-package", "1.0.0")] == set()

    def test_sends_correct_querybatch_payload(self):
        """Test that the HTTP request body is correctly formatted for querybatch."""
        # Arrange
        pkg = make_package("flask", ProjectPackagesRegistry.PYPI)
        session = make_session([{"results": [{"vulns": []}]}])
        api = CveApiOsv(session)

        # Act
        api.get_cves_batch([(pkg, "2.0.0")])

        # Assert
        call_kwargs = session.post.call_args
        assert call_kwargs[0][0].endswith("/querybatch")
        payload = call_kwargs[1]["json"]
        assert payload == {"queries": [{"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "2.0.0"}]}

    @pytest.mark.parametrize(
        "score,expected_severity",
        [
            (9.5, Severity.CRITICAL),
            (7.5, Severity.HIGH),
            (5.0, Severity.MEDIUM),
            (2.0, Severity.LOW),
        ],
    )
    def test_severity_mapping(self, score: float, expected_severity: Severity):
        """Test that OSV score values are correctly mapped to Severity levels."""
        # Arrange
        pkg = make_package("pkg")
        vuln = {**make_osv_vuln(), "severity": [{"score": score}]}
        session = make_session([{"results": [{"vulns": [vuln]}]}])
        api = CveApiOsv(session)

        # Act
        result = api.get_cves_batch([(pkg, "1.0.0")])

        # Assert
        cve = next(iter(result[("pkg", "1.0.0")]))
        assert cve.severity == expected_severity

    def test_handles_pagination_via_next_page_token(self):
        """Test that results with next_page_token trigger additional requests and are merged."""
        # Arrange
        pkg = make_package("vulnerable-pkg")
        session = make_session(
            [
                # Initial batch response — has a next_page_token
                {"results": [{"vulns": [make_osv_vuln("GHSA-page1-001")], "next_page_token": "token-abc"}]},
                # Follow-up paginated response — no more pages
                {"results": [{"vulns": [make_osv_vuln("GHSA-page2-002")]}]},
            ]
        )
        api = CveApiOsv(session)

        # Act
        result = api.get_cves_batch([(pkg, "1.0.0")])

        # Assert
        cves = result[("vulnerable-pkg", "1.0.0")]
        assert len(cves) == 2
        cve_ids = {cve.id for cve in cves}
        assert cve_ids == {"GHSA-page1-001", "GHSA-page2-002"}
        assert session.post.call_count == 2

    def test_pagination_request_includes_page_token(self):
        """Test that the pagination follow-up request includes the correct page_token."""
        # Arrange
        pkg = make_package("pkg")
        session = make_session(
            [
                {"results": [{"vulns": [], "next_page_token": "my-token-xyz"}]},
                {"results": [{"vulns": []}]},
            ]
        )
        api = CveApiOsv(session)

        # Act
        api.get_cves_batch([(pkg, "1.0.0")])

        # Assert — second call must include the page_token
        second_call_payload = session.post.call_args_list[1][1]["json"]
        assert second_call_payload["queries"][0]["page_token"] == "my-token-xyz"
