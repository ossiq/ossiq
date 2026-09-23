# pylint: disable=protected-access
"""
Tests for CveApiOsv in ossiq.adapters.api_osv module.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from ossiq.adapters.api_osv import CveApiOsv
from ossiq.clients.batch import BatchClient
from ossiq.domain.common import CveDatabase, DataSourceStatus, ProjectPackagesRegistry
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
            result = api.get_cves_batch([]).data

        assert result == {}
        mock_run.assert_not_called()

    def test_returns_correct_mapping_for_single_package(self):
        """Test that a single package result is keyed by (package.name, version)."""
        pkg = make_package("lodash")
        version = "4.17.20"
        chunk_data = {("lodash", "4.17.20"): [make_osv_vuln("GHSA-xxxx-0001")]}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_cves_batch([(pkg, version)]).data

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
            result = api.get_cves_batch([(pkg_a, "18.0.0"), (pkg_b, "4.18.0")]).data

        assert len(result[("react", "18.0.0")]) == 1
        assert len(result[("express", "4.18.0")]) == 2

    def test_returns_empty_set_for_package_with_no_cves(self):
        """Test that a package with no vulnerabilities maps to an empty set."""
        pkg = make_package("safe-package")
        chunk_data = {("safe-package", "1.0.0"): []}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_cves_batch([(pkg, "1.0.0")]).data

        assert result[("safe-package", "1.0.0")] == set()

    def test_package_missing_from_batch_result_maps_to_empty_set(self):
        """Test that packages absent from batch results (e.g. dropped chunk) default to empty set."""
        pkg = make_package("pkg")
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([{}])):
            result = api.get_cves_batch([(pkg, "1.0.0")]).data

        assert result[("pkg", "1.0.0")] == set()

    def test_merges_results_from_multiple_chunks(self):
        """Test that CVE results from multiple yielded chunks are combined."""
        pkg_a = make_package("react")
        pkg_b = make_package("express")
        chunk1 = {("react", "18.0.0"): [make_osv_vuln("GHSA-aaaa-0001")]}
        chunk2 = {("express", "4.18.0"): [make_osv_vuln("GHSA-bbbb-0002")]}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk1, chunk2])):
            result = api.get_cves_batch([(pkg_a, "18.0.0"), (pkg_b, "4.18.0")]).data

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
            result = api.get_cves_batch([(pkg_a, "18.0.0"), (pkg_b, "4.18.0")]).data

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
            result = api.get_cves_batch([(pkg, "1.0.0")]).data

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
            result = api.get_cves_batch([(pkg, "1.0.0")]).data

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
            result = api.get_cves_batch([(pkg, "1.0.0")]).data

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
            result = api.get_cves_batch([(pkg, "1.0.0")]).data

        cve = next(iter(result[("pkg", "1.0.0")]))
        assert cve.severity == expected_severity

    @pytest.mark.parametrize(
        "vector,expected_severity",
        [
            # N2: OSV's real data shape for CVSS_V3/V4 severity entries is a full vector string,
            # never a bare number - the test above never exercised this and is why the bug
            # (float() on a vector string, silently swallowed, always falling back to MEDIUM)
            # went unnoticed. Reference scores verified against known CVEs / the CVSS spec's own
            # worked examples; see adapters/test_cvss.py for the full derivation.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Severity.CRITICAL),  # Log4Shell, 10.0
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Severity.CRITICAL),  # 9.8
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", Severity.HIGH),  # 7.5
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", Severity.MEDIUM),  # 6.1
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L", Severity.LOW),  # 1.8
        ],
    )
    def test_severity_mapping_from_a_real_cvss_vector_string(self, vector: str, expected_severity: Severity):
        pkg = make_package("pkg")
        vuln = {**make_osv_vuln(), "severity": [{"type": "CVSS_V3", "score": vector}]}
        chunk_data = {("pkg", "1.0.0"): [vuln]}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_cves_batch([(pkg, "1.0.0")]).data

        cve = next(iter(result[("pkg", "1.0.0")]))
        assert cve.severity == expected_severity

    def test_a_cvss_v4_vector_falls_back_to_medium_rather_than_crashing(self):
        """v4.0 scoring isn't implemented (see adapters/cvss.py) - must degrade to the same
        MEDIUM fallback as any other unparseable severity, not raise or silently misclassify.
        """
        pkg = make_package("pkg")
        v4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        vuln = {**make_osv_vuln(), "severity": [{"type": "CVSS_V4", "score": v4_vector}]}
        chunk_data = {("pkg", "1.0.0"): [vuln]}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_cves_batch([(pkg, "1.0.0")]).data

        cve = next(iter(result[("pkg", "1.0.0")]))
        assert cve.severity == Severity.MEDIUM

    def test_multiple_severity_entries_takes_the_highest(self):
        """A CVSS_V3 vector alongside a bare-numeric entry from a different type - the max across
        both parsing paths must win, not just whichever came first in the list.
        """
        pkg = make_package("pkg")
        vuln = {
            **make_osv_vuln(),
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L"},  # 1.8
                {"type": "Ubuntu", "score": "9.1"},  # a bare-numeric entry from a non-CVSS source
            ],
        }
        chunk_data = {("pkg", "1.0.0"): [vuln]}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_cves_batch([(pkg, "1.0.0")]).data

        cve = next(iter(result[("pkg", "1.0.0")]))
        assert cve.severity == Severity.CRITICAL


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


class TestFetchStatus:
    """B4: get_cves_batch() must expose whether OSV actually answered, not just what it returned -
    a firewalled host and "checked, no CVEs" must not be indistinguishable via the data alone.
    The status rides back with the payload rather than being left on the instance.
    """

    def test_empty_input_is_ok(self):
        api = CveApiOsv(MagicMock())
        assert api.get_cves_batch([]).status == DataSourceStatus.OK

    def test_host_unreachable_is_unreachable_not_ok(self):
        """The report's literal scenario: api.osv.dev firewalled. Every request raises
        ConnectionError; get_cves_batch must not silently look like "checked, zero CVEs".
        """
        pkg = make_package("lodash")
        api = CveApiOsv(MagicMock())
        api._strategy.config.max_retries = 1  # keep the test fast

        with (
            patch.object(api.session, "post", side_effect=requests.ConnectionError("blocked")),
            patch("ossiq.clients.batch.time.sleep"),
        ):
            fetch = api.get_cves_batch([(pkg, "4.17.20")])

        assert fetch.data[("lodash", "4.17.20")] == set()
        assert fetch.status == DataSourceStatus.UNREACHABLE

    def test_quota_exhausted_is_rate_limited(self):
        pkg = make_package("lodash")
        api = CveApiOsv(MagicMock())
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 429
        resp.headers = {"x-ratelimit-remaining": "0"}

        with patch.object(api.session, "post", return_value=resp):
            fetch = api.get_cves_batch([(pkg, "4.17.20")])

        assert fetch.status == DataSourceStatus.RATE_LIMITED

    def test_successful_fetch_is_ok(self):
        pkg = make_package("lodash")
        chunk_data = {("lodash", "4.17.20"): [make_osv_vuln("GHSA-xxxx-0001")]}
        api = CveApiOsv(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            fetch = api.get_cves_batch([(pkg, "4.17.20")])

        assert fetch.status == DataSourceStatus.OK


class TestExtractSummary:
    """B6: a CVE record must carry a description, not just an identifier."""

    def test_uses_summary_when_present(self):
        from ossiq.adapters.api_osv import CveApiOsv

        assert CveApiOsv.extract_summary({"summary": "Header leak on redirect", "details": "prose"}) == (
            "Header leak on redirect"
        )

    def test_falls_back_to_details_when_summary_absent(self):
        """Many PYSEC records carry only 'details'; those came back blank before this fix."""
        from ossiq.adapters.api_osv import CveApiOsv

        raw = {"details": "Requests leaks the Proxy-Authorization header.\n\nFurther paragraphs."}
        assert CveApiOsv.extract_summary(raw) == "Requests leaks the Proxy-Authorization header."

    def test_truncates_a_very_long_first_line(self):
        from ossiq.adapters.api_osv import CveApiOsv

        out = CveApiOsv.extract_summary({"details": "x" * 500})
        assert len(out) == 300 and out.endswith("...")

    def test_empty_when_neither_field_is_present(self):
        from ossiq.adapters.api_osv import CveApiOsv

        assert CveApiOsv.extract_summary({}) == ""
