"""Tests for CVE enrichment in service/project/prefetch.py."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, call, patch

from packaging.version import Version

from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.domain.common import (
    ConstraintType,
    CveDatabase,
    DataSourceStatus,
    ProjectPackagesRegistry,
    RateLimitBudget,
    ScanStep,
    SourceFetch,
)
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.exceptions import UnknownPackageVersion
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion
from ossiq.service.project.models import DependencyDescriptor
from ossiq.service.project.prefetch import enrich_cves_with_epss_and_fix_age, forecast_github_budget
from ossiq.service.project.scan import ScanProgress, apply_cutoff_date, prefetch_scan_data
from ossiq.settings import Settings


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
    epss_client.get_epss_batch.return_value = SourceFetch({"CVE-2024-0003": 0.75})
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
    ).data

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
    epss_client.get_epss_batch.return_value = SourceFetch(
        {
            "CVE-2024-0001": 0.0,
            "CVE-2024-0002": 0.9,
        }
    )
    registry = make_registry({})

    result = enrich_cves_with_epss_and_fix_age(
        {("foo", "1.0.0"): {cve}},
        epss_client,
        registry,
        now=None,
    ).data

    enriched = next(iter(result[("foo", "1.0.0")]))
    assert enriched.epss == 0.9


def test_zero_epss_score_is_not_treated_as_missing():
    cve = make_cve("CVE-2024-0001")
    epss_client = MagicMock()
    epss_client.get_epss_batch.return_value = SourceFetch({"CVE-2024-0001": 0.0})
    registry = make_registry({})

    result = enrich_cves_with_epss_and_fix_age(
        {("foo", "1.0.0"): {cve}},
        epss_client,
        registry,
        now=None,
    ).data

    enriched = next(iter(result[("foo", "1.0.0")]))
    assert enriched.epss == 0.0


def test_missing_registry_fix_release_leaves_age_unknown():
    cve = make_cve("CVE-2024-0001", fix_versions=("1.1.0",))
    epss_client = MagicMock()
    epss_client.get_epss_batch.return_value = SourceFetch({})
    registry = make_registry({"foo": [make_release("1.2.0", "2025-01-01T00:00:00Z")]})

    result = enrich_cves_with_epss_and_fix_age(
        {("foo", "1.0.0"): {cve}},
        epss_client,
        registry,
        now=datetime(2025, 1, 11, tzinfo=UTC),
    ).data

    enriched = next(iter(result[("foo", "1.0.0")]))
    assert enriched.fix_available is True
    assert enriched.fix_age_days is None


def test_unknown_package_versions_do_not_abort_enrichment():
    cve = make_cve("CVE-2024-0001", fix_versions=("1.1.0",))
    epss_client = MagicMock()
    epss_client.get_epss_batch.return_value = SourceFetch({"CVE-2024-0001": 0.4})
    registry = make_registry({})
    registry.package_versions.side_effect = UnknownPackageVersion("foo")

    result = enrich_cves_with_epss_and_fix_age(
        {("foo", "1.0.0"): {cve}},
        epss_client,
        registry,
        now=datetime(2025, 1, 11, tzinfo=UTC),
    ).data

    enriched = next(iter(result[("foo", "1.0.0")]))
    assert enriched.epss == 0.4
    assert enriched.fix_age_days is None


def test_empty_map_does_not_call_external_services():
    epss_client = MagicMock()
    registry = MagicMock()

    fetch = enrich_cves_with_epss_and_fix_age({}, epss_client, registry, now=None)
    assert fetch.data == {}
    # Nothing to enrich is not a degraded EPSS source.
    assert fetch.status == DataSourceStatus.OK
    epss_client.get_epss_batch.assert_not_called()
    registry.package_versions.assert_not_called()


def test_prefetch_scan_data_enriches_cves_after_osv_fetch():
    raw_cve_map = {("foo", "1.0.0"): set()}
    enriched_cve_map = {("foo", "1.0.0"): {make_cve("CVE-2024-0001")}}
    sources = MagicMock()
    sources.allow_prerelease = False
    sources.allow_prerelease_packages = ()
    sources.packages_registry.packages_info_batch.return_value = {}
    sources.cve_database.get_cves_batch.return_value = SourceFetch(raw_cve_map, DataSourceStatus.PARTIAL)
    sources.get_source_code_provider.return_value.repositories_info_batch.return_value = SourceFetch(
        {}, DataSourceStatus.OK
    )
    on_step_start = MagicMock()
    on_step_done = MagicMock()
    progress = ScanProgress(on_step_start=on_step_start, on_step_done=on_step_done)
    now = datetime(2025, 1, 11, tzinfo=UTC)

    with patch(
        "ossiq.service.project.scan.enrich_cves_with_epss_and_fix_age",
        return_value=SourceFetch(enriched_cve_map, DataSourceStatus.RATE_LIMITED),
    ) as enrich:
        result = prefetch_scan_data(sources, [], now, progress)

    # Enrichment runs on the raw map OSV returned, not on the SourceFetch wrapper.
    enrich.assert_called_once_with(
        raw_cve_map,
        sources.epss_score_database,
        sources.packages_registry,
        now,
    )
    assert result.cve_map == enriched_cve_map
    repo_status = DataSourceStatus.OK
    cve_status = DataSourceStatus.PARTIAL
    assert on_step_start.call_args_list == [
        call(ScanStep.PACKAGES),
        call(ScanStep.REPOSITORIES),
        call(ScanStep.VULNERABILITIES),
        call(ScanStep.EPSS),
        call(ScanStep.VERSIONS),
    ]
    # Every outcome now carries its diagnostics: the status says the step degraded, the
    # diagnostics say why, and the renderer needs both to name a cause.
    assert [(args[0], args[1]) for args, _ in on_step_done.call_args_list] == [
        (ScanStep.REPOSITORIES, repo_status),
        (ScanStep.VULNERABILITIES, cve_status),
        (ScanStep.EPSS, DataSourceStatus.RATE_LIMITED),
    ]
    assert result.data_completeness.status_for(ScanStep.EPSS) == DataSourceStatus.RATE_LIMITED


def _make_dep(canonical_name: str, dependency_path: list[str] | None) -> DependencyDescriptor:
    return DependencyDescriptor(
        name=canonical_name,
        canonical_name=canonical_name,
        version="1.0.0",
        is_optional=False,
        dependency_path=dependency_path,
        version_constraint=None,
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
    )


def _make_package(name: str, repo_url: str) -> Package:
    return Package(
        registry=ProjectPackagesRegistry.PYPI,
        name=name,
        latest_version=None,
        next_version=None,
        repo_url=repo_url,
    )


def test_prefetch_scan_data_fetches_stability_signals_for_direct_deps_only():
    direct_dep = _make_dep("foo", dependency_path=None)
    transitive_dep = _make_dep("bar", dependency_path=["foo"])
    sources = MagicMock()
    sources.allow_prerelease = False
    sources.allow_prerelease_packages = ()
    sources.settings.stability = True
    sources.settings.responsiveness_enabled.return_value = True
    sources.packages_registry.packages_info_batch.return_value = {
        "foo": _make_package("foo", "https://github.com/org/foo"),
        "bar": _make_package("bar", "https://github.com/org/bar"),
    }
    sources.packages_registry.package_versions.return_value = []
    sources.cve_database.get_cves_batch.return_value = SourceFetch({})
    sources.epss_score_database.get_epss_batch.return_value = SourceFetch({})
    progress = ScanProgress()
    now = datetime(2025, 1, 11, tzinfo=UTC)

    with (
        patch(
            "ossiq.service.project.scan.prefetch_source_code_repositories_info",
            return_value=SourceFetch({}),
        ) as repos_info,
        patch("ossiq.service.project.scan.prefetch_repository_commits", return_value=SourceFetch({})) as commits,
        patch("ossiq.service.project.scan.prefetch_repository_readmes", return_value=SourceFetch({})),
        patch("ossiq.service.project.scan.prefetch_repository_activity", return_value=SourceFetch({})) as activity,
    ):
        prefetch_scan_data(sources, [direct_dep, transitive_dep], now, progress)

    assert repos_info.call_args.args[1] == {"https://github.com/org/foo", "https://github.com/org/bar"}
    assert commits.call_args.args[2] == {"https://github.com/org/foo"}
    assert activity.call_args.args[2] == {"https://github.com/org/foo"}


def test_prefetch_scan_data_skips_activity_when_responsiveness_disabled():
    direct_dep = _make_dep("foo", dependency_path=None)
    sources = MagicMock()
    sources.allow_prerelease = False
    sources.allow_prerelease_packages = ()
    sources.settings.stability = True
    sources.settings.responsiveness_enabled.return_value = False
    sources.packages_registry.packages_info_batch.return_value = {
        "foo": _make_package("foo", "https://github.com/org/foo"),
    }
    sources.packages_registry.package_versions.return_value = []
    sources.cve_database.get_cves_batch.return_value = SourceFetch({})

    with (
        patch("ossiq.service.project.scan.prefetch_source_code_repositories_info", return_value=SourceFetch({})),
        patch("ossiq.service.project.scan.prefetch_repository_commits", return_value=SourceFetch({})),
        patch("ossiq.service.project.scan.prefetch_repository_readmes", return_value=SourceFetch({})),
        patch("ossiq.service.project.scan.prefetch_repository_activity", return_value=SourceFetch({})) as activity,
    ):
        result = prefetch_scan_data(sources, [direct_dep], datetime(2025, 1, 11, tzinfo=UTC), MagicMock())

    activity.assert_not_called()
    assert result.activity == {}


class TestForecastGithubBudget:
    """A quota that can't cover the scan is worth saying before the scan spends minutes finding
    out - and a warm cache means the run may never touch the network to discover it at all."""

    def provider(self, *budgets: RateLimitBudget) -> MagicMock:
        provider = MagicMock()
        provider.rate_limit_budgets.return_value = budgets
        return provider

    def test_forecast_counts_every_repo_for_rest_and_direct_repos_for_graphql(self):
        provider = self.provider(
            RateLimitBudget(resource="core", limit=5000, remaining=4000),
            RateLimitBudget(resource="graphql", limit=5000, remaining=5000),
        )
        forecast = forecast_github_budget(
            provider,
            ["https://github.com/org/a", "https://github.com/org/b"],
            ["https://github.com/org/a"],
            stability=True,
            responsiveness=True,
        )

        assert {budget.resource: budget.needed for budget in forecast} == {"core": 4, "graphql": 2}

    def test_a_disabled_channel_is_not_forecast_for(self):
        provider = self.provider(
            RateLimitBudget(resource="core", remaining=100),
            RateLimitBudget(resource="graphql", remaining=100),
        )
        forecast = forecast_github_budget(
            provider,
            ["https://github.com/org/a"],
            ["https://github.com/org/a"],
            stability=False,
            responsiveness=False,
        )

        assert [budget.resource for budget in forecast] == ["core"]

    def test_non_github_urls_are_not_counted(self):
        provider = self.provider(RateLimitBudget(resource="core", remaining=100))
        forecast = forecast_github_budget(
            provider,
            ["https://gitlab.com/org/a", "https://github.com/org/b"],
            [],
            stability=True,
            responsiveness=True,
        )

        assert [budget.needed for budget in forecast] == [1]

    def test_nothing_to_fetch_asks_github_nothing(self):
        provider = self.provider(RateLimitBudget(resource="core", remaining=100))

        assert forecast_github_budget(provider, [], [], stability=True, responsiveness=True) == ()
        provider.rate_limit_budgets.assert_not_called()


def test_prefetch_scan_data_records_data_completeness_per_step():
    """B4: the report's actual scenario, end to end through prefetch_scan_data — a firewalled
    OSV host and an exhausted GitHub quota must show up in the result's data_completeness, not
    just vanish into an empty-looking but "successful" cve_map/repositories_info.
    """
    direct_dep = _make_dep("foo", dependency_path=None)
    sources = MagicMock()
    sources.allow_prerelease = False
    sources.allow_prerelease_packages = ()
    sources.settings.stability = False
    sources.packages_registry.packages_info_batch.return_value = {
        "foo": _make_package("foo", "https://github.com/org/foo"),
    }
    sources.packages_registry.package_versions.return_value = []

    # GitHub: quota exhausted mid-fetch.
    provider = sources.get_source_code_provider.return_value
    provider.repositories_info_batch.return_value = SourceFetch({}, DataSourceStatus.RATE_LIMITED)

    # OSV: host unreachable, every chunk failed.
    sources.cve_database.get_cves_batch.return_value = SourceFetch({}, DataSourceStatus.UNREACHABLE)

    # EPSS: fine, so the two degraded sources above are the only ones reported.
    sources.epss_score_database.get_epss_batch.return_value = SourceFetch({})

    result = prefetch_scan_data(sources, [direct_dep], datetime(2025, 1, 11, tzinfo=UTC), MagicMock())

    assert result.data_completeness.status_for(ScanStep.REPOSITORIES) == DataSourceStatus.RATE_LIMITED
    assert result.data_completeness.status_for(ScanStep.VULNERABILITIES) == DataSourceStatus.UNREACHABLE
    assert result.data_completeness.status_for(ScanStep.EPSS) == DataSourceStatus.OK
    assert result.data_completeness.overall == DataSourceStatus.RATE_LIMITED


def test_prefetch_scan_data_completeness_is_ok_on_a_clean_run():
    direct_dep = _make_dep("foo", dependency_path=None)
    sources = MagicMock()
    sources.allow_prerelease = False
    sources.allow_prerelease_packages = ()
    sources.settings.stability = False
    sources.packages_registry.packages_info_batch.return_value = {
        "foo": _make_package("foo", "https://github.com/org/foo"),
    }
    sources.packages_registry.package_versions.return_value = []
    sources.get_source_code_provider.return_value.repositories_info_batch.return_value = SourceFetch({})
    sources.cve_database.get_cves_batch.return_value = SourceFetch({})
    sources.epss_score_database.get_epss_batch.return_value = SourceFetch({})

    result = prefetch_scan_data(sources, [direct_dep], datetime(2025, 1, 11, tzinfo=UTC), MagicMock())

    assert result.data_completeness.overall == DataSourceStatus.OK
    assert result.data_completeness.degraded_steps == {}


class TestApplyCutoffDatePrerelease:
    """D6 reproduction: the cutoff-date override of latest_version picks pre-releases."""

    @staticmethod
    def release(version: str, published: str) -> PackageVersion:
        return PackageVersion(
            version=version,
            license=None,
            package_url=f"https://pypi.org/project/pydantic/{version}/",
            declared_dependencies={},
            published_date_iso=published,
            is_prerelease=Version(version).is_prerelease,
        )

    def test_cutoff_keeps_latest_version_stable(self):
        registry = PackageRegistryApiPypi(Settings())
        releases = [
            self.release("1.10.26", "2025-06-01T00:00:00Z"),
            self.release("2.13.0", "2026-07-01T00:00:00Z"),
            self.release("2.14.0b1", "2026-09-01T00:00:00Z"),
        ]
        package = Package(
            registry=ProjectPackagesRegistry.PYPI,
            name="pydantic",
            latest_version="2.13.0",
            next_version=None,
            repo_url=None,
        )

        with patch.object(registry, "package_versions", return_value=releases):
            apply_cutoff_date({"pydantic": package}, registry, datetime(2026, 9, 8, tzinfo=UTC))

        assert package.latest_version == "2.13.0"

    def test_cutoff_keeps_the_prerelease_when_prereleases_are_allowed(self):
        registry = PackageRegistryApiPypi(Settings())
        releases = [
            self.release("2.13.0", "2026-07-01T00:00:00Z"),
            self.release("2.14.0b1", "2026-09-01T00:00:00Z"),
        ]
        package = Package(
            registry=ProjectPackagesRegistry.PYPI,
            name="pydantic",
            latest_version="2.13.0",
            next_version=None,
            repo_url=None,
        )

        with patch.object(registry, "package_versions", return_value=releases):
            apply_cutoff_date(
                {"pydantic": package},
                registry,
                datetime(2026, 9, 8, tzinfo=UTC),
                allow_prerelease_packages=("pydantic",),
            )

        assert package.latest_version == "2.14.0b1"
