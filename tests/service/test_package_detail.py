"""`ossiq info` must not re-decide what `ossiq status` already decided.

build_installed_detail used to re-run the whole update-strategy selector over every matched record
with no recommendation - direct records included - with degraded inputs: an unfiltered
versions_since, no transitive_by_name, no installed_names, no validator and no engine context. The
two surfaces could therefore disagree about the same package, which is the contradictory-surfaces
class the scan pipeline exists to prevent.
"""

from unittest.mock import MagicMock

import pytest
from packaging.version import Version

from ossiq.domain.common import (
    ConstraintType,
    EngineContext,
    ProjectPackagesRegistry,
    RecommendationRung,
    RegistryStatus,
)
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.package import (
    RULE_PACKAGE_DEPRECATED,
    RULE_PACKAGE_QUARANTINED,
    RULE_VERSION_DEPRECATED,
    PackageDetailResult,
    PackageWarning,
    build_installed_detail,
    build_package_insight,
    evaluate_package_rules,
    fetch_prospective_detail,
    registry_status_note,
)
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.settings import Settings

CONSTRAINT = ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json")


def pv(
    version: str,
    *,
    is_prerelease: bool = False,
    is_deprecated: bool = False,
    deprecation_message: str | None = None,
) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso="2024-01-01T00:00:00Z",
        is_prerelease=is_prerelease,
        is_deprecated=is_deprecated,
        deprecation_message=deprecation_message,
    )


def make_record(
    name: str = "pkg",
    *,
    installed: str = "1.0.0",
    recommended: str | None = None,
    rung: RecommendationRung | None = None,
    dependency_path: list[str] | None = None,
    version_constraint: str | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version=installed,
        latest_version="2.0.0",
        versions_diff_index=VersionsDifference(installed, "2.0.0", 5, "DIFF_MAJOR"),
        time_lag_days=None,
        releases_lag=None,
        cve=[],
        constraint_info=CONSTRAINT,
        recommended_version=recommended,
        recommended_from_rung=rung,
        dependency_path=dependency_path,
        version_constraint=version_constraint,
        compatibility=CompatibilityFacts(),
    )


def make_sources(releases: list[PackageVersion]) -> MagicMock:
    sources = MagicMock()
    sources.allow_prerelease = False
    sources.release_cutoff = None
    registry = sources.packages_registry
    registry.package_registry = ProjectPackagesRegistry.NPM
    registry.package_versions.return_value = releases

    # Real ordering: the solver and clamp both compare versions, and a MagicMock comparator
    # silently orders by object identity.
    def compare(v1: str, v2: str) -> int:
        p1, p2 = Version(v1), Version(v2)
        return -1 if p1 < p2 else (1 if p1 > p2 else 0)

    registry.compare_versions.side_effect = compare
    registry.newest_version.side_effect = lambda candidates: (
        max(list(candidates), key=lambda p: Version(p.version)) if list(candidates) else None
    )
    registry.package_info.return_value = Package(
        registry=ProjectPackagesRegistry.NPM,
        name="pkg",
        latest_version="2.0.0",
        next_version=None,
        repo_url=None,
    )
    registry.fetch_downloads_recent.return_value = None
    return sources


def make_scan(records: list[ScanRecord], transitive: list[ScanRecord] | None = None) -> ScanResult:
    return ScanResult(
        project_name="proj",
        packages_registry="NPM",
        project_path=".",
        production_packages=records,
        optional_packages=[],
        transitive_packages=transitive or [],
        engine_context=EngineContext(),
    )


class TestDirectRecordsAreNotReDecided:
    def test_a_direct_record_the_selector_blanked_stays_blank(self) -> None:
        """The selector withholding a recommendation is a decision, not a gap to fill in."""
        record = make_record(recommended=None, version_constraint="~1.0.0")
        sources = make_sources([pv("1.0.0"), pv("2.0.0")])

        build_installed_detail([record], make_scan([record]), "pkg", sources, Settings())

        assert record.recommended_version is None
        assert record.recommended_from_rung is None

    def test_an_up_to_date_direct_record_is_left_alone(self) -> None:
        record = make_record(installed="2.0.0", recommended=None)
        sources = make_sources([pv("2.0.0")])

        build_installed_detail([record], make_scan([record]), "pkg", sources, Settings())

        assert record.recommended_version is None

    def test_a_direct_record_keeps_the_scan_recommendation(self) -> None:
        """info reports status's number, verbatim - the whole point of not re-running the selector."""
        record = make_record(recommended="1.5.0", rung=RecommendationRung.IN_RANGE)
        sources = make_sources([pv("1.0.0"), pv("1.5.0"), pv("2.0.0")])

        detail = build_installed_detail([record], make_scan([record]), "pkg", sources, Settings())

        assert record.recommended_version == "1.5.0"
        assert record.recommended_from_rung == RecommendationRung.IN_RANGE
        assert detail.insight is not None
        assert detail.insight.recommended_version == "1.5.0"

    def test_no_prerelease_can_be_surfaced_that_status_would_not_show(self) -> None:
        """The old synthetic versions_since came straight from package_versions(), which is not
        prerelease-filtered the way prefetch_versions_since is."""
        record = make_record(recommended=None)
        sources = make_sources([pv("1.0.0"), pv("3.0.0-rc.1", is_prerelease=True)])

        build_installed_detail([record], make_scan([record]), "pkg", sources, Settings())

        assert record.recommended_version is None


class TestTransitiveRecordsStillGetADisplayValue:
    def test_an_up_to_date_transitive_record_is_solved_for_display(self) -> None:
        """Transitive records are solved with skip_current=True during the scan, so this is the
        display gap the re-solve exists to fill."""
        record = make_record(installed="1.0.0", recommended=None, dependency_path=["parent"])
        sources = make_sources([pv("1.0.0")])
        scan = make_scan([], transitive=[record])

        build_installed_detail([record], scan, "pkg", sources, Settings())

        assert record.recommended_version == "1.0.0"

    def test_the_transitive_solve_does_not_run_the_strategy_selector(self) -> None:
        """The strategy is direct-dependencies-only in v1 (see ScanRecord.strategy_selection), so a
        transitive record must not come back carrying a selector verdict."""
        record = make_record(installed="1.0.0", recommended=None, dependency_path=["parent"])
        sources = make_sources([pv("1.0.0"), pv("2.0.0")])
        scan = make_scan([], transitive=[record])

        build_installed_detail([record], scan, "pkg", sources, Settings())

        assert record.strategy_selection is None


# ---------------------------------------------------------------------------
# The registry's verdict: deprecated / archived / quarantined packages and releases
# ---------------------------------------------------------------------------

LEFT_PAD_NOTE = "use String.prototype.padStart()"


def make_package(
    status: RegistryStatus | None,
    *,
    registry: ProjectPackagesRegistry = ProjectPackagesRegistry.NPM,
    message: str | None = None,
    latest: str = "2.0.0",
) -> Package:
    return Package(
        registry=registry,
        name="pkg",
        latest_version=latest,
        next_version=None,
        repo_url=None,
        registry_status=status,
        deprecation_message=message,
    )


def rules_for(
    package: Package,
    versions: list[PackageVersion],
    *,
    requested: str | None = None,
    recommended: str | None = None,
) -> dict[str, PackageWarning]:
    insight = build_package_insight(
        package, versions, Settings(), recommended_version=recommended, requested_version=requested
    )
    return {warning.rule_id: warning for warning in evaluate_package_rules(insight, Settings())}


class TestRetiredPackageRules:
    def test_a_deprecated_npm_package_is_a_critical_warning_quoting_the_maintainer(self) -> None:
        warnings = rules_for(make_package(RegistryStatus.DEPRECATED, message=LEFT_PAD_NOTE), [pv("1.0.0"), pv("2.0.0")])

        warning = warnings[RULE_PACKAGE_DEPRECATED]
        assert warning.severity == "critical"
        assert warning.message == f'Deprecated on npm: "{LEFT_PAD_NOTE}" — look for an alternative'

    def test_an_archived_pypi_package_names_pypi_and_has_no_quote_to_make(self) -> None:
        package = make_package(RegistryStatus.ARCHIVED, registry=ProjectPackagesRegistry.PYPI)

        warning = rules_for(package, [pv("1.0.0"), pv("2.0.0")])[RULE_PACKAGE_DEPRECATED]

        assert warning.severity == "critical"
        assert warning.message == "Archived on PyPI — look for an alternative"

    def test_a_quarantined_package_is_critical_and_not_called_deprecated(self) -> None:
        package = make_package(RegistryStatus.QUARANTINED, registry=ProjectPackagesRegistry.PYPI)

        warnings = rules_for(package, [pv("1.0.0"), pv("2.0.0")])

        assert RULE_PACKAGE_DEPRECATED not in warnings
        assert warnings[RULE_PACKAGE_QUARANTINED].severity == "critical"
        assert "Quarantined on PyPI" in warnings[RULE_PACKAGE_QUARANTINED].message

    @pytest.mark.parametrize("status", [RegistryStatus.ACTIVE, None])
    def test_an_active_or_unjudged_package_raises_none_of_them(self, status: RegistryStatus | None) -> None:
        warnings = rules_for(make_package(status), [pv("1.0.0"), pv("2.0.0")])

        assert not {RULE_PACKAGE_DEPRECATED, RULE_PACKAGE_QUARANTINED, RULE_VERSION_DEPRECATED} & warnings.keys()

    def test_the_registrys_own_words_are_carried_verbatim_for_the_renderer_to_escape(self) -> None:
        warning = rules_for(make_package(RegistryStatus.DEPRECATED, message="see [docs] now"), [pv("1.0.0")])[
            RULE_PACKAGE_DEPRECATED
        ]

        assert '"see [docs] now"' in warning.message


class TestRequestedReleaseRule:
    VERSIONS = [pv("1.0.0"), pv("2.0.0", is_deprecated=True, deprecation_message="update to 3"), pv("3.0.0")]

    def test_a_deprecated_release_asked_for_by_name_is_critical_and_points_at_the_recommendation(self) -> None:
        warnings = rules_for(
            make_package(RegistryStatus.ACTIVE, latest="3.0.0"), self.VERSIONS, requested="2.0.0", recommended="3.0.0"
        )

        warning = warnings[RULE_VERSION_DEPRECATED]
        assert warning.severity == "critical"
        assert warning.message == 'Version 2.0.0 is deprecated on npm: "update to 3" — use 3.0.0 instead'

    def test_no_pointer_when_the_recommendation_is_the_release_itself(self) -> None:
        warning = rules_for(make_package(RegistryStatus.ACTIVE), self.VERSIONS, requested="2.0.0", recommended="2.0.0")[
            RULE_VERSION_DEPRECATED
        ]

        assert "instead" not in warning.message

    def test_a_release_that_is_not_deprecated_raises_nothing(self) -> None:
        warnings = rules_for(make_package(RegistryStatus.ACTIVE), self.VERSIONS, requested="3.0.0", recommended="3.0.0")

        assert RULE_VERSION_DEPRECATED not in warnings

    def test_a_release_that_does_not_exist_raises_nothing(self) -> None:
        warnings = rules_for(make_package(RegistryStatus.ACTIVE), self.VERSIONS, requested="9.9.9", recommended="3.0.0")

        assert RULE_VERSION_DEPRECATED not in warnings

    def test_without_a_request_the_releases_are_not_judged(self) -> None:
        warnings = rules_for(make_package(RegistryStatus.ACTIVE), self.VERSIONS, recommended="3.0.0")

        assert RULE_VERSION_DEPRECATED not in warnings

    def test_it_is_redundant_once_the_whole_package_is_retired(self) -> None:
        warnings = rules_for(
            make_package(RegistryStatus.DEPRECATED, message=LEFT_PAD_NOTE),
            [pv("2.0.0", is_deprecated=True)],
            requested="2.0.0",
            recommended="2.0.0",
        )

        assert RULE_PACKAGE_DEPRECATED in warnings
        assert RULE_VERSION_DEPRECATED not in warnings


class TestRegistryStatusNote:
    @pytest.mark.parametrize("status", [None, RegistryStatus.ACTIVE])
    def test_nothing_to_state_for_an_active_or_unjudged_package(self, status: RegistryStatus | None) -> None:
        assert registry_status_note(status, ProjectPackagesRegistry.NPM, "ignored") is None

    def test_names_the_registry_and_quotes_the_message(self) -> None:
        note = registry_status_note(RegistryStatus.DEPRECATED, ProjectPackagesRegistry.NPM, LEFT_PAD_NOTE)

        assert note == f'deprecated on npm: "{LEFT_PAD_NOTE}"'

    def test_omits_the_quote_when_there_is_no_message(self) -> None:
        assert registry_status_note(RegistryStatus.ARCHIVED, ProjectPackagesRegistry.PYPI, None) == "archived on PyPI"

    def test_omits_the_registry_when_the_caller_does_not_know_it(self) -> None:
        assert registry_status_note(RegistryStatus.DEPRECATED, None, "moved") == 'deprecated: "moved"'


def prospective_sources(package: Package, releases: list[PackageVersion]) -> MagicMock:
    sources = make_sources(releases)
    sources.packages_registry.package_info.return_value = package
    sources.cve_database.get_cves_batch.return_value.data = {}
    return sources


def recommended_of(detail: PackageDetailResult) -> str | None:
    assert detail.insight is not None
    return detail.insight.recommended_version


class TestProspectiveAddOfARetiredPackage:
    """`fetch_prospective_detail`, which `ossiq add` and `ossiq_evaluate_dependency` both run."""

    def test_left_pad_is_blocked_with_the_npm_message(self) -> None:
        # Every release deprecated, as on npm: the old soft penalty is the same for all of them.
        releases = [pv(v, is_deprecated=True, deprecation_message=LEFT_PAD_NOTE) for v in ("1.0.0", "1.1.0", "1.3.0")]
        package = make_package(RegistryStatus.DEPRECATED, message=LEFT_PAD_NOTE, latest="1.3.0")

        detail = fetch_prospective_detail("pkg", prospective_sources(package, releases), Settings())

        critical = [w for w in detail.warnings if w.severity == "critical"]
        assert [w.rule_id for w in critical] == [RULE_PACKAGE_DEPRECATED]
        assert LEFT_PAD_NOTE in critical[0].message
        # Nothing clean to prefer, so a forced add gets the usual pick rather than none.
        assert recommended_of(detail) == "1.3.0"

    def test_a_deprecated_release_is_never_recommended_for_a_live_package(self) -> None:
        # Three deprecated releases above one clean one: the solver's penalty alone is 10k against a
        # 5k-per-rank preference, so 4.0.0 still wins unless deprecated releases are not candidates.
        releases = [pv("1.0.0")] + [pv(f"{major}.0.0", is_deprecated=True) for major in (2, 3, 4)]
        package = make_package(RegistryStatus.ACTIVE, latest="4.0.0")

        detail = fetch_prospective_detail("pkg", prospective_sources(package, releases), Settings())

        assert recommended_of(detail) == "1.0.0"
        assert not [w for w in detail.warnings if w.severity == "critical"]

    def test_the_requested_release_reaches_the_rule(self) -> None:
        releases = [pv("1.0.0"), pv("2.0.0", is_deprecated=True, deprecation_message="update to 3"), pv("3.0.0")]
        package = make_package(RegistryStatus.ACTIVE, latest="3.0.0")

        detail = fetch_prospective_detail(
            "pkg", prospective_sources(package, releases), Settings(), requested_version="2.0.0"
        )

        assert recommended_of(detail) == "3.0.0"
        warning = next(w for w in detail.warnings if w.rule_id == RULE_VERSION_DEPRECATED)
        assert warning.message == 'Version 2.0.0 is deprecated on npm: "update to 3" — use 3.0.0 instead'

    def test_asking_for_nothing_in_particular_judges_only_the_package(self) -> None:
        releases = [pv("1.0.0"), pv("2.0.0", is_deprecated=True)]
        package = make_package(RegistryStatus.ACTIVE, latest="2.0.0")

        detail = fetch_prospective_detail("pkg", prospective_sources(package, releases), Settings())

        assert RULE_VERSION_DEPRECATED not in {w.rule_id for w in detail.warnings}
