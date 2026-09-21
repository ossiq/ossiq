"""Tests for the EPSS x maintenance-state triage matrix."""

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


class TestCveDataUnavailable:
    """N1: the exploit-side mirror of TestUnknownStability - absent CVE evidence must not read as
    confirmed-clean when the fetch itself was degraded, the same way absent stability evidence
    must not read as unstable.
    """

    def test_reported_scenario_empty_cves_from_a_degraded_fetch(self) -> None:
        """The report's own scenario: OSV unreachable, cves ends up empty, but the field must say
        so honestly rather than claiming a clean result it never checked.
        """
        result = triage([], STABLE, cve_data_unavailable=True)
        assert result.action == ACTION_RETAIN
        assert result.cve_data_unavailable is True
        assert "could not be retrieved" in result.reason
        assert "no significant" not in result.reason.lower()

    def test_default_is_false_and_unchanged_wording(self) -> None:
        """Existing, confirmed-clean callers must see exactly the old reason text - this must not
        become a blanket disclaimer on every retain verdict.
        """
        result = triage([], STABLE)
        assert result.cve_data_unavailable is False
        assert result.reason == "No significant exploit or stability signal."

    def test_field_is_set_regardless_of_which_action_fires(self) -> None:
        """A caller must be able to check cve_data_unavailable without first checking which
        branch produced the result - it is not only meaningful on the retain path.
        """
        evict = triage([make_cve(0.42)], UNSTABLE, cve_data_unavailable=True)
        patch = triage([make_cve(0.42)], STABLE, cve_data_unavailable=True)
        refactor = triage([], UNSTABLE, cve_data_unavailable=True)
        assert evict.cve_data_unavailable is True
        assert patch.cve_data_unavailable is True
        assert refactor.cve_data_unavailable is True

    def test_real_evidence_on_this_package_is_not_overridden_by_a_degraded_scan(self) -> None:
        """A scan-level 'partial' status does not mean *this* package's chunk failed - if a real,
        scored CVE came through for it, that evidence is used exactly as normal. Only the
        wording of an otherwise-empty result changes.
        """
        result = triage([make_cve(0.42)], STABLE, cve_data_unavailable=True)
        assert result.action == ACTION_PATCH
        assert result.reason == "Active exploit probability, and the repository is active enough to ship a fix."
