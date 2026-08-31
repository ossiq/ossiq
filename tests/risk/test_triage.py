"""Tests for the EPSS x CSI triage matrix."""

from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.risk.triage import (
    ACTION_EVICT,
    ACTION_PATCH,
    ACTION_REFACTOR,
    ACTION_RETAIN,
    triage,
)

STABLE = False  # repository measured and active
UNSTABLE = True  # repository measured and dormant


def make_cve(epss: float | None, cve_id: str = "CVE-2026-0001") -> CVE:
    return CVE(
        id=cve_id,
        cve_ids=(cve_id,),
        source=CveDatabase.OSV,
        package_name="example",
        package_registry=ProjectPackagesRegistry.PYPI,
        summary="example advisory",
        severity=Severity.HIGH,
        affected_versions=("1.0.0",),
        published="2026-01-01T00:00:00Z",
        link="https://example.test/advisory",
        epss=epss,
    )


class TestMatrixCells:
    def test_high_epss_unstable_repo_evicts(self) -> None:
        result = triage([make_cve(0.42)], UNSTABLE)
        assert result.action == ACTION_EVICT
        assert result.max_epss == 0.42

    def test_high_epss_stable_repo_patches(self) -> None:
        result = triage([make_cve(0.42)], STABLE)
        assert result.action == ACTION_PATCH

    def test_low_epss_unstable_repo_schedules_refactor(self) -> None:
        result = triage([make_cve(0.01)], UNSTABLE)
        assert result.action == ACTION_REFACTOR

    def test_low_epss_stable_repo_retains(self) -> None:
        result = triage([make_cve(0.01)], STABLE)
        assert result.action == ACTION_RETAIN

    def test_no_cves_stable_repo_retains(self) -> None:
        result = triage([], STABLE)
        assert result.action == ACTION_RETAIN
        assert result.max_epss is None


class TestUnknownStability:
    def test_unknown_stability_is_not_unstable(self) -> None:
        """A repository we could not measure must never be marked for refactoring."""
        assert triage([make_cve(0.01)], None).action == ACTION_RETAIN

    def test_unknown_stability_still_patches_an_active_threat(self) -> None:
        assert triage([make_cve(0.42)], None).action == ACTION_PATCH

    def test_no_cves_unstable_repo_still_refactors(self) -> None:
        """The strategic pipeline works with no CVE data at all — that is the point of it."""
        assert triage([], UNSTABLE).action == ACTION_REFACTOR


class TestNoiseThreshold:
    def test_below_noise_cves_are_suppressed_not_dropped(self) -> None:
        result = triage([make_cve(0.0001)], STABLE)
        assert result.action == ACTION_RETAIN
        assert result.max_epss is None
        assert result.suppressed_cves == 1

    def test_unscored_cves_are_not_counted_as_suppressed(self) -> None:
        result = triage([make_cve(None)], STABLE)
        assert result.max_epss is None
        assert result.suppressed_cves == 0

    def test_max_is_taken_over_qualifying_cves_only(self) -> None:
        result = triage([make_cve(0.0001, "CVE-1"), make_cve(0.2, "CVE-2")], STABLE)
        assert result.max_epss == 0.2
        assert result.suppressed_cves == 1

    def test_threshold_boundaries_are_inclusive(self) -> None:
        assert triage([make_cve(0.005)], STABLE).suppressed_cves == 0
        assert triage([make_cve(0.10)], STABLE).action == ACTION_PATCH

    def test_custom_thresholds(self) -> None:
        result = triage([make_cve(0.2)], STABLE, exploit=0.5)
        assert result.action == ACTION_RETAIN
