"""Tests for ossiq.risk.p_supplychain."""

import pytest

from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VERSION_LATEST, VersionsDifference
from ossiq.risk.p_supplychain import FRESH_HAZARD_WEIGHT, compute_p_supplychain
from ossiq.service.project.models import ScanRecord


def make_record(*, version_age_days: int | None = None) -> ScanRecord:
    return ScanRecord(
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
        version_age_days=version_age_days,
    )


def expected_hazard(age: int, cooldown_days: int, fresh_hazard_weight: float) -> float:
    """Reference formula, independent of the implementation under test."""
    clamped_age = max(age, 0)
    if clamped_age >= cooldown_days:
        return 0.0
    return fresh_hazard_weight * (1.0 - clamped_age / cooldown_days)


@pytest.mark.parametrize("version_age_days", [0, 1, 3, 6, 7, 365])
def test_matches_expected_hazard_formula(version_age_days: int) -> None:
    result = compute_p_supplychain(
        make_record(version_age_days=version_age_days), fresh_hazard_weight=FRESH_HAZARD_WEIGHT
    )

    assert result == pytest.approx(expected_hazard(version_age_days, 7, FRESH_HAZARD_WEIGHT))


def test_unknown_version_age_returns_none() -> None:
    assert compute_p_supplychain(make_record(version_age_days=None)) is None


def test_negative_age_clamps_to_zero() -> None:
    negative = compute_p_supplychain(make_record(version_age_days=-5))
    zero = compute_p_supplychain(make_record(version_age_days=0))

    assert negative == zero


def test_custom_cooldown_period() -> None:
    result = compute_p_supplychain(
        make_record(version_age_days=10), cooldown_days=14, fresh_hazard_weight=FRESH_HAZARD_WEIGHT
    )

    assert result == pytest.approx(expected_hazard(10, 14, FRESH_HAZARD_WEIGHT))


def test_custom_fresh_hazard_weight_changes_the_result() -> None:
    default_weight = compute_p_supplychain(make_record(version_age_days=3))
    doubled_weight = compute_p_supplychain(make_record(version_age_days=3), fresh_hazard_weight=FRESH_HAZARD_WEIGHT * 2)

    assert default_weight is not None
    assert doubled_weight == pytest.approx(default_weight * 2)


def test_fresh_hazard_weight_defaults_to_the_module_constant() -> None:
    explicit = compute_p_supplychain(make_record(version_age_days=3), fresh_hazard_weight=FRESH_HAZARD_WEIGHT)
    default = compute_p_supplychain(make_record(version_age_days=3))

    assert default == pytest.approx(explicit)


@pytest.mark.parametrize("cooldown_days", [0, -3])
def test_non_positive_cooldown_disables_the_hazard(cooldown_days: int) -> None:
    assert compute_p_supplychain(make_record(version_age_days=5), cooldown_days=cooldown_days) == 0.0


@pytest.mark.parametrize("version_age_days", [0, 1, 3, 6, 7, 365])
def test_result_stays_within_unit_bounds(version_age_days: int) -> None:
    result = compute_p_supplychain(make_record(version_age_days=version_age_days))

    assert result is not None
    assert 0.0 <= result <= 1.0


def test_scan_record_defaults_p_supplychain_to_none() -> None:
    assert make_record().p_supplychain is None
