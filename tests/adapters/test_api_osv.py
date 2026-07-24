# pylint: disable=protected-access
"""
Tests for CveApiOsv in ossiq.adapters.api_osv module.
"""

from unittest.mock import MagicMock, patch

import pytest

from ossiq.adapters.api_osv import CveApiOsv
from ossiq.clients.batch import BatchClient
from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import Severity
from ossiq.domain.package import Package


def make_package(name: str, registry: ProjectPackagesRegistry = ProjectPackagesRegistry.NPM) -> Package:
    return Package(registry=registry, name=name, latest_version="1.0.0", next_version=None, repo_url=None)


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
        """Test that an empty input list returns an empty dict without calling run_batch."""
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch") as mock_run:
            result = api.get_cves_batch([])

        assert result == {}
        mock_run.assert_not_called()

    def test_returns_correct_mapping_for_single_package(self):
        """Test that a single package result is keyed by (package.name, version)."""
        pkg = make_package("lodash")
        version = "4.17.20"
        chunk_data = {("lodash", "4.17.20"): [make_osv_vuln("GHSA-xxxx-0001")]}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_cves_batch([(pkg, version)])

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
        pkg_a = make_package("react")
        pkg_b = make_package("express")
        chunk_data = {
            ("react", "18.0.0"): [make_osv_vuln("GHSA-aaaa-0001")],
            ("express", "4.18.0"): [make_osv_vuln("GHSA-bbbb-0002"), make_osv_vuln("GHSA-bbbb-0003")],
        }
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_cves_batch([(pkg_a, "18.0.0"), (pkg_b, "4.18.0")])

        assert len(result[("react", "18.0.0")]) == 1
        assert len(result[("express", "4.18.0")]) == 2

    def test_returns_empty_set_for_package_with_no_cves(self):
        """Test that a package with no vulnerabilities maps to an empty set."""
        pkg = make_package("safe-package")
        chunk_data = {("safe-package", "1.0.0"): []}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_cves_batch([(pkg, "1.0.0")])

        assert result[("safe-package", "1.0.0")] == set()

    def test_package_missing_from_batch_result_maps_to_empty_set(self):
        """Test that packages absent from batch results (e.g. dropped chunk) default to empty set."""
        pkg = make_package("pkg")
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([{}])):
            result = api.get_cves_batch([(pkg, "1.0.0")])

        assert result[("pkg", "1.0.0")] == set()

    def test_merges_results_from_multiple_chunks(self):
        """Test that CVE results from multiple yielded chunks are combined."""
        pkg_a = make_package("react")
        pkg_b = make_package("express")
        chunk1 = {("react", "18.0.0"): [make_osv_vuln("GHSA-aaaa-0001")]}
        chunk2 = {("express", "4.18.0"): [make_osv_vuln("GHSA-bbbb-0002")]}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk1, chunk2])):
            result = api.get_cves_batch([(pkg_a, "18.0.0"), (pkg_b, "4.18.0")])

        assert len(result[("react", "18.0.0")]) == 1
        assert len(result[("express", "4.18.0")]) == 1

    def test_fetches_details_once_per_unique_id_and_reuses_aliases(self):
        pkg_a = make_package("react")
        pkg_b = make_package("express")
        stub = {"id": "GHSA-shared-0001", "modified": "2024-01-01T00:00:00Z"}
        full_record = make_osv_vuln("GHSA-shared-0001")
        api = CveApiOsv(MagicMock())

        with (
            patch.object(
                api._batch_client,
                "run_batch",
                return_value=iter(
                    [
                        {
                            ("react", "18.0.0"): [stub],
                            ("express", "4.18.0"): [stub],
                        }
                    ]
                ),
            ),
            patch.object(
                api._details_batch_client,
                "run_batch",
                return_value=iter([{"GHSA-shared-0001": full_record}]),
            ) as details_run,
        ):
            result = api.get_cves_batch([(pkg_a, "18.0.0"), (pkg_b, "4.18.0")])

        details_run.assert_called_once_with(["GHSA-shared-0001"])
        assert next(iter(result[("react", "18.0.0")])).cve_ids == ("CVE-2024-0001",)
        assert next(iter(result[("express", "4.18.0")])).cve_ids == ("CVE-2024-0001",)

    def test_accumulates_discovery_pages_before_fetching_details(self):
        pkg = make_package("pkg")
        stub_a = {"id": "GHSA-page1-0001"}
        stub_b = {"id": "GHSA-page2-0002"}
        full_a = make_osv_vuln("GHSA-page1-0001")
        full_b = make_osv_vuln("GHSA-page2-0002")
        api = CveApiOsv(MagicMock())

        with (
            patch.object(
                api._batch_client,
                "run_batch",
                return_value=iter(
                    [
                        {("pkg", "1.0.0"): [stub_a]},
                        {("pkg", "1.0.0"): [stub_b]},
                    ]
                ),
            ),
            patch.object(
                api._details_batch_client,
                "run_batch",
                return_value=iter(
                    [
                        {"GHSA-page1-0001": full_a},
                        {"GHSA-page2-0002": full_b},
                    ]
                ),
            ) as details_run,
        ):
            result = api.get_cves_batch([(pkg, "1.0.0")])

        details_run.assert_called_once_with(["GHSA-page1-0001", "GHSA-page2-0002"])
        assert {cve.id for cve in result[("pkg", "1.0.0")]} == {
            "GHSA-page1-0001",
            "GHSA-page2-0002",
        }

    def test_failed_detail_fetch_keeps_minimal_cve(self):
        pkg = make_package("pkg")
        stub = {"id": "GHSA-missing-details", "modified": "2024-01-01T00:00:00Z"}
        api = CveApiOsv(MagicMock())

        with (
            patch.object(
                api._batch_client,
                "run_batch",
                return_value=iter([{("pkg", "1.0.0"): [stub]}]),
            ),
            patch.object(api._details_batch_client, "run_batch", return_value=iter([])),
        ):
            result = api.get_cves_batch([(pkg, "1.0.0")])

        cve = next(iter(result[("pkg", "1.0.0")]))
        assert cve.id == "GHSA-missing-details"
        assert cve.cve_ids == ()
        assert cve.summary == ""
        assert cve.severity == Severity.MEDIUM

    def test_empty_discovery_skips_details_stage(self):
        pkg = make_package("safe-package")
        api = CveApiOsv(MagicMock())

        with (
            patch.object(api._batch_client, "run_batch", return_value=iter([])),
            patch.object(api._details_batch_client, "run_batch") as details_run,
        ):
            result = api.get_cves_batch([(pkg, "1.0.0")])

        details_run.assert_not_called()
        assert result[("safe-package", "1.0.0")] == set()

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
        pkg = make_package("pkg")
        vuln = {**make_osv_vuln(), "severity": [{"score": score}]}
        chunk_data = {("pkg", "1.0.0"): [vuln]}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_cves_batch([(pkg, "1.0.0")])

        cve = next(iter(result[("pkg", "1.0.0")]))
        assert cve.severity == expected_severity


class TestExtractFixVersions:
    def test_excludes_other_ecosystems_and_packages(self):
        api = CveApiOsv(MagicMock())
        package = make_package("foo")
        osv_entry = {
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "foo"},
                    "ranges": [{"events": [{"fixed": "1.2.4"}]}],
                },
                {
                    "package": {"ecosystem": "PyPI", "name": "foo"},
                    "ranges": [{"events": [{"fixed": "3.7.0"}]}],
                },
                {
                    "package": {"ecosystem": "npm", "name": "@foo/helper"},
                    "ranges": [{"events": [{"fixed": "5.0.0"}]}],
                },
            ]
        }

        assert api.extract_fix_versions(osv_entry, package) == ("1.2.4",)

    def test_collects_fixed_events_across_ranges(self):
        api = CveApiOsv(MagicMock())
        package = make_package("foo")
        osv_entry = {
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "foo"},
                    "ranges": [
                        {
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.2.4"},
                            ]
                        },
                        {
                            "events": [
                                {"introduced": "2.0.0"},
                                {"fixed": "2.0.3"},
                            ]
                        },
                    ],
                }
            ]
        }

        assert api.extract_fix_versions(osv_entry, package) == ("1.2.4", "2.0.3")

    def test_returns_empty_tuple_without_matching_fixed_event(self):
        api = CveApiOsv(MagicMock())
        package = make_package("foo")
        osv_entry = {
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "foo"},
                    "ranges": [{"events": [{"introduced": "0"}, {"last_affected": "1.2.3"}]}],
                }
            ]
        }

        assert api.extract_fix_versions(osv_entry, package) == ()
