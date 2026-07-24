"""Tests for CVE enrichment in service/project/prefetch.py."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, call, patch

from packaging.version import Version

from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.exceptions import UnknownPackageVersion
from ossiq.domain.version import PackageVersion
from ossiq.service.project.prefetch import enrich_cves_with_epss_and_fix_age
from ossiq.service.project.scan import prefetch_scan_data


def make_cve(
    cve_id: str,
    *,
    aliases: tuple[str, ...] = (),
    fix_versions: tuple[str, ...] = (),
    package_name: str = "foo",
) -> CVE:
    return CVE(
        id=cve_id,
        cve_ids=aliases,
        source=CveDatabase.OSV,
        package_name=package_name,
        package_registry=ProjectPackagesRegistry.PYPI,
        summary="Test vulnerability",
        severity=Severity.HIGH,
        affected_versions=("1.0.0",),
        published="2024-01-01T00:00:00Z",
        link=f"https://osv.dev/{cve_id}",
        fix_available=bool(fix_versions),
        fix_versions=fix_versions,
    )


def make_release(version: str, published: str | None) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso=published,
    )


def make_registry(versions_by_package: dict[str, list[PackageVersion]]) -> MagicMock:
    registry = MagicMock()
    registry.package_versions.side_effect = lambda package_name: versions_by_package.get(package_name, [])

    def compare_versions(left: str, right: str) -> int:
        left_version = Version(left)
        right_version = Version(right)
        return (left_version > right_version) - (left_version < right_version)

    registry.compare_versions.side_effect = compare_versions
    return registry


def test_enriches_epss_and_uses_nearest_fix_release_age():
    fixable = make_cve(
        "GHSA-xxxx-0001",
        aliases=("GHSA-yyyy-0002", "CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0001"),
        fix_versions=("2.0.0", "not-a-registry-version", "1.2.0"),
    )
    unscored = make_cve("CVE-2024-0002", package_name="bar")
    cve_map = {
        ("foo", "1.0.0"): {fixable},
        ("bar", "3.0.0"): {unscored},
    }
    epss_client = MagicMock()
    epss_client.get_epss_batch.return_value = {"CVE-2024-0003": 0.75}
    registry = make_registry(
        {
            "foo": [
                make_release("1.2.0", "2025-01-01T00:00:00Z"),
                make_release("2.0.0", "2025-01-09T00:00:00Z"),
            ]
        }
    )

    result = enrich_cves_with_epss_and_fix_age(
        cve_map,
        epss_client,
        registry,
        now=datetime(2025, 1, 11, tzinfo=UTC),
    )

    enriched_fixable = next(iter(result[("foo", "1.0.0")]))
    enriched_unscored = next(iter(result[("bar", "3.0.0")]))
    assert enriched_fixable.epss == 0.75
    assert enriched_fixable.fix_age_days == 10
    assert enriched_unscored.epss is None
    assert enriched_unscored.fix_age_days is None
    assert fixable.epss is None
    assert fixable.fix_age_days is None

    epss_client.get_epss_batch.assert_called_once()
    requested_ids = set(epss_client.get_epss_batch.call_args.args[0])
    assert requested_ids == {
        "GHSA-xxxx-0001",
        "GHSA-yyyy-0002",
        "CVE-2024-0001",
        "CVE-2024-0002",
        "CVE-2024-0003",
    }
    registry.package_versions.assert_called_once_with("foo")


def test_uses_highest_epss_score_across_cve_aliases():
    cve = make_cve("CVE-2024-0001", aliases=("CVE-2024-0002",))
    epss_client = MagicMock()
    epss_client.get_epss_batch.return_value = {
        "CVE-2024-0001": 0.0,
        "CVE-2024-0002": 0.9,
    }
    registry = make_registry({})

    result = enrich_cves_with_epss_and_fix_age(
        {("foo", "1.0.0"): {cve}},
        epss_client,
        registry,
        now=None,
    )

    enriched = next(iter(result[("foo", "1.0.0")]))
    assert enriched.epss == 0.9


def test_zero_epss_score_is_not_treated_as_missing():
    cve = make_cve("CVE-2024-0001")
    epss_client = MagicMock()
    epss_client.get_epss_batch.return_value = {"CVE-2024-0001": 0.0}
    registry = make_registry({})

    result = enrich_cves_with_epss_and_fix_age(
        {("foo", "1.0.0"): {cve}},
        epss_client,
        registry,
        now=None,
    )

    enriched = next(iter(result[("foo", "1.0.0")]))
    assert enriched.epss == 0.0


def test_missing_registry_fix_release_leaves_age_unknown():
    cve = make_cve("CVE-2024-0001", fix_versions=("1.1.0",))
    epss_client = MagicMock()
    epss_client.get_epss_batch.return_value = {}
    registry = make_registry({"foo": [make_release("1.2.0", "2025-01-01T00:00:00Z")]})

    result = enrich_cves_with_epss_and_fix_age(
        {("foo", "1.0.0"): {cve}},
        epss_client,
        registry,
        now=datetime(2025, 1, 11, tzinfo=UTC),
    )

    enriched = next(iter(result[("foo", "1.0.0")]))
    assert enriched.fix_available is True
    assert enriched.fix_age_days is None


def test_unknown_package_versions_do_not_abort_enrichment():
    cve = make_cve("CVE-2024-0001", fix_versions=("1.1.0",))
    epss_client = MagicMock()
    epss_client.get_epss_batch.return_value = {"CVE-2024-0001": 0.4}
    registry = make_registry({})
    registry.package_versions.side_effect = UnknownPackageVersion("foo")

    result = enrich_cves_with_epss_and_fix_age(
        {("foo", "1.0.0"): {cve}},
        epss_client,
        registry,
        now=datetime(2025, 1, 11, tzinfo=UTC),
    )

    enriched = next(iter(result[("foo", "1.0.0")]))
    assert enriched.epss == 0.4
    assert enriched.fix_age_days is None


def test_empty_map_does_not_call_external_services():
    epss_client = MagicMock()
    registry = MagicMock()

    assert enrich_cves_with_epss_and_fix_age({}, epss_client, registry, now=None) == {}
    epss_client.get_epss_batch.assert_not_called()
    registry.package_versions.assert_not_called()


def test_prefetch_scan_data_enriches_cves_after_osv_fetch():
    raw_cve_map = {("foo", "1.0.0"): set()}
    enriched_cve_map = {("foo", "1.0.0"): {make_cve("CVE-2024-0001")}}
    sources = MagicMock()
    sources.allow_prerelease = False
    sources.allow_prerelease_packages = ()
    sources.packages_registry.packages_info_batch.return_value = {}
    sources.cve_database.get_cves_batch.return_value = raw_cve_map
    step = MagicMock()
    now = datetime(2025, 1, 11, tzinfo=UTC)

    with patch(
        "ossiq.service.project.scan.enrich_cves_with_epss_and_fix_age",
        return_value=enriched_cve_map,
    ) as enrich:
        result = prefetch_scan_data(sources, [], now, step)

    enrich.assert_called_once_with(
        raw_cve_map,
        sources.epss_score_database,
        sources.packages_registry,
        now,
    )
    assert result.cve_map == enriched_cve_map
    assert step.call_args_list == [
        call("packages"),
        call("repositories"),
        call("vulnerabilities"),
        call("epss"),
        call("versions"),
    ]
