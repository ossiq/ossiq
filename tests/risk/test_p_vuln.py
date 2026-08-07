"""Tests for ossiq.risk.p_vuln."""

import math

import pytest

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VERSION_LATEST, VersionsDifference
from ossiq.risk.p_vuln import NEGLIGENCE_BUMP_WEIGHT, NEGLIGENT_FIX_AGE_DAYS, compute_p_vuln
from ossiq.service.project.models import ScanRecord


def make_cve(
    *,
    epss: float | None = 0.5,
    reachable: bool | None = None,
    fix_age_days: int | None = None,
    fix_available: bool = False,
) -> CVE:
    return CVE(
        id="CVE-2024-0001",
        cve_ids=("CVE-2024-0001",),
        source=CveDatabase.OSV,
        package_name="example",
        package_registry=ProjectPackagesRegistry.PYPI,
        summary="example vulnerability",
        severity=Severity.CRITICAL,
        affected_versions=("1.0.0",),
        published=None,
        link="https://example.test/advisory",
        epss=epss,
        fix_available=fix_available,
        fix_age_days=fix_age_days,
        reachable=reachable,
    )


def expected_p_vuln(
    cves: list[tuple[float, bool | None, int | None]],
    window_days: float,
    horizon_days: int = 365,
) -> float:
    """Reference formula, independent of the implementation under test.

    Each tuple is `(epss, reachable, fix_age_days)`. Callers only use this for
    cases with a known, non-negative window/horizon and complete EPSS data;
    the None-returning validation branches are tested directly instead.
    """
    lambda_total = 0.0
    for epss, reachable, _fix_age_days in cves:
        clamped_epss = max(0.0, min(epss, 0.99))
        factor = {True: 1.0, None: 0.5, False: 0.1}[reachable]
        lambda_total += -math.log(1 - clamped_epss * factor) / 365

    p_vuln = 1 - math.exp(-lambda_total * min(window_days, horizon_days))

    if any(fix_age_days is not None and fix_age_days > 30 for _, _, fix_age_days in cves):
        p_vuln = 1 - (1 - p_vuln) * (1 - 0.15)

    return max(0.0, min(p_vuln, 1.0))


def test_hand_computed_single_cve_exact_half() -> None:
    """-log(1 - 0.5)/365 * 365 == log(2); 1 - exp(-log(2)) == 0.5 exactly."""
    result = compute_p_vuln([make_cve(epss=0.5, reachable=True)], 365)

    assert result == pytest.approx(0.5)


def test_hand_computed_single_cve_partial_window() -> None:
    result = compute_p_vuln([make_cve(epss=0.5, reachable=True)], 100)

    assert result == pytest.approx(0.17296092595785162)


@pytest.mark.parametrize("reachable", [True, None, False])
def test_all_reachability_states(reachable: bool | None) -> None:
    result = compute_p_vuln([make_cve(epss=0.5, reachable=reachable)], 100)

    assert result == pytest.approx(expected_p_vuln([(0.5, reachable, None)], 100))


def test_multiple_cves_sum_hazard_rates() -> None:
    cves = [make_cve(epss=0.3, reachable=True), make_cve(epss=0.3, reachable=True)]

    result = compute_p_vuln(cves, 50)

    assert result == pytest.approx(expected_p_vuln([(0.3, True, None), (0.3, True, None)], 50))


def test_window_beyond_default_horizon_caps_at_365_days() -> None:
    cves = [make_cve(epss=0.5, reachable=True)]

    assert compute_p_vuln(cves, 1000) == pytest.approx(0.5)


def test_custom_horizon_caps_the_window() -> None:
    cves = [make_cve(epss=0.5, reachable=True)]

    capped = compute_p_vuln(cves, 500, horizon_days=200)

    assert capped == pytest.approx(compute_p_vuln(cves, 200))
    assert capped == pytest.approx(expected_p_vuln([(0.5, True, None)], 200))


@pytest.mark.parametrize("epss", [0.99, 1.0, 2.5])
def test_epss_above_point_99_clamps_to_point_99(epss: float) -> None:
    result = compute_p_vuln([make_cve(epss=epss, reachable=True)], 100)

    assert result == pytest.approx(expected_p_vuln([(0.99, True, None)], 100))


def test_negative_epss_clamps_to_zero() -> None:
    assert compute_p_vuln([make_cve(epss=-0.5, reachable=True)], 100) == 0.0


def test_missing_epss_on_the_only_cve_returns_none() -> None:
    assert compute_p_vuln([make_cve(epss=None)], 100) is None


def test_missing_epss_on_any_cve_returns_none() -> None:
    cves = [make_cve(epss=0.5, reachable=True), make_cve(epss=None, reachable=True)]

    assert compute_p_vuln(cves, 100) is None


def test_unknown_window_with_cves_returns_none() -> None:
    assert compute_p_vuln([make_cve()], None) is None


def test_negative_window_returns_none() -> None:
    assert compute_p_vuln([make_cve()], -1.0) is None


def test_negative_horizon_returns_none() -> None:
    assert compute_p_vuln([make_cve()], 100, horizon_days=-1) is None


def test_zero_cves_is_zero_with_a_known_window() -> None:
    assert compute_p_vuln([], 100) == 0.0


def test_zero_cves_is_zero_even_with_an_unknown_window() -> None:
    assert compute_p_vuln([], None) == 0.0


def test_zero_cves_is_zero_even_with_a_negative_window() -> None:
    assert compute_p_vuln([], -5) == 0.0


def test_accepts_a_one_shot_iterable() -> None:
    cves = iter([make_cve(epss=0.5, reachable=True)])

    assert compute_p_vuln(cves, 100) == pytest.approx(0.17296092595785162)


def test_fix_age_at_boundary_30_does_not_bump() -> None:
    without_bump = compute_p_vuln([make_cve(epss=0.5, reachable=True)], 100)
    cves = [make_cve(epss=0.5, reachable=True, fix_age_days=NEGLIGENT_FIX_AGE_DAYS)]

    assert compute_p_vuln(cves, 100) == pytest.approx(without_bump)


def test_fix_age_one_day_past_boundary_bumps() -> None:
    base = compute_p_vuln([make_cve(epss=0.5, reachable=True)], 100)
    assert base is not None
    cves = [make_cve(epss=0.5, reachable=True, fix_age_days=NEGLIGENT_FIX_AGE_DAYS + 1)]

    assert compute_p_vuln(cves, 100) == pytest.approx(1 - (1 - base) * (1 - NEGLIGENCE_BUMP_WEIGHT))


def test_fix_available_alone_without_a_fix_age_does_not_bump() -> None:
    without_bump = compute_p_vuln([make_cve(epss=0.5, reachable=True)], 100)
    cves = [make_cve(epss=0.5, reachable=True, fix_available=True, fix_age_days=None)]

    assert compute_p_vuln(cves, 100) == pytest.approx(without_bump)


def test_negligence_bump_unions_across_cves_when_only_one_qualifies() -> None:
    cves = [
        make_cve(epss=0.5, reachable=True, fix_age_days=10),
        make_cve(epss=0.1, reachable=True, fix_age_days=40),
    ]
    base = expected_p_vuln([(0.5, True, None), (0.1, True, None)], 100)
    expected = 1 - (1 - base) * (1 - NEGLIGENCE_BUMP_WEIGHT)

    assert compute_p_vuln(cves, 100) == pytest.approx(expected)


def test_negligence_bump_applies_once_not_per_qualifying_cve() -> None:
    cves = [
        make_cve(epss=0.3, reachable=True, fix_age_days=40),
        make_cve(epss=0.3, reachable=True, fix_age_days=40),
    ]
    base = expected_p_vuln([(0.3, True, None), (0.3, True, None)], 50)
    single_bump = 1 - (1 - base) * (1 - NEGLIGENCE_BUMP_WEIGHT)

    result = compute_p_vuln(cves, 50)

    assert result == pytest.approx(single_bump)
    assert result != pytest.approx(1 - (1 - base) * (1 - NEGLIGENCE_BUMP_WEIGHT) ** 2)


def test_result_stays_within_unit_bounds_even_under_extreme_inputs() -> None:
    cves = [make_cve(epss=0.99, reachable=True, fix_age_days=60) for _ in range(20)]

    result = compute_p_vuln(cves, 100_000, horizon_days=100_000)

    assert result is not None
    assert 0.0 <= result <= 1.0


def test_cve_defaults_reachable_to_none() -> None:
    assert make_cve().reachable is None


def test_scan_record_defaults_p_vuln_to_none() -> None:
    record = ScanRecord(
        package_name="example",
        dependency_name="example",
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="1.0.0",
        versions_diff_index=VersionsDifference("1.0.0", "1.0.0", VERSION_LATEST, "ignored"),
        time_lag_days=0,
        releases_lag=0,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
    )

    assert record.p_vuln is None
