"""`ossiq info` must not re-decide what `ossiq status` already decided.

build_installed_detail used to re-run the whole update-strategy selector over every matched record
with no recommendation - direct records included - with degraded inputs: an unfiltered
versions_since, no transitive_by_name, no installed_names, no validator and no engine context. The
two surfaces could therefore disagree about the same package, which is the contradictory-surfaces
class the scan pipeline exists to prevent.
"""

from unittest.mock import MagicMock

from packaging.version import Version

from ossiq.domain.common import ConstraintType, EngineContext, ProjectPackagesRegistry, RecommendationRung
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.package import build_installed_detail
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.settings import Settings

CONSTRAINT = ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json")


def pv(version: str, *, is_prerelease: bool = False) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso="2024-01-01T00:00:00Z",
        is_prerelease=is_prerelease,
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
