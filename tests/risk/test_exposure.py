"""Tests for ossiq.risk.exposure."""

import math

import pytest

from ossiq.risk.exposure import (
    EXECUTION_MULTIPLIER_DEFAULT,
    EXECUTION_MULTIPLIER_TRUE,
    REACH_LOG_WEIGHT,
    TIER_MULTIPLIER,
    DependencyTier,
    combine_incident_probability,
    compute_expected_exposure,
    compute_impact,
    fitness_projection,
)

# ============================================================================
# compute_impact
# ============================================================================


class TestComputeImpact:
    @pytest.mark.parametrize("tier", ["runtime", "build", "dev"])
    def test_tier_multiplier_applied(self, tier: DependencyTier) -> None:
        result = compute_impact(tier, normalized_fan_out=0.0, transitive_count=0, runs_code_at_install=False)

        assert result == pytest.approx(TIER_MULTIPLIER[tier] * 0.5)

    def test_fan_out_zero_uses_half_multiplier(self) -> None:
        result = compute_impact("runtime", normalized_fan_out=0.0, transitive_count=0, runs_code_at_install=False)

        assert result == pytest.approx(0.5)

    def test_fan_out_one_uses_full_multiplier(self) -> None:
        result = compute_impact("runtime", normalized_fan_out=1.0, transitive_count=0, runs_code_at_install=False)

        assert result == pytest.approx(1.0)

    def test_fan_out_above_one_clamps_to_one(self) -> None:
        result = compute_impact("runtime", normalized_fan_out=5.0, transitive_count=0, runs_code_at_install=False)

        assert result == pytest.approx(1.0)

    def test_fan_out_below_zero_clamps_to_zero(self) -> None:
        result = compute_impact("runtime", normalized_fan_out=-5.0, transitive_count=0, runs_code_at_install=False)

        assert result == pytest.approx(0.5)

    def test_transitive_count_matches_hand_computed_log1p(self) -> None:
        result = compute_impact("runtime", normalized_fan_out=0.0, transitive_count=99, runs_code_at_install=False)
        expected = 0.5 * (1.0 + REACH_LOG_WEIGHT * math.log1p(99))

        assert result == pytest.approx(expected)

    def test_negative_transitive_count_clamps_to_zero(self) -> None:
        result = compute_impact("runtime", normalized_fan_out=0.0, transitive_count=-10, runs_code_at_install=False)

        assert result == pytest.approx(compute_impact("runtime", 0.0, 0, False))

    def test_runs_code_at_install_true_applies_execution_penalty(self) -> None:
        result = compute_impact("runtime", normalized_fan_out=0.0, transitive_count=0, runs_code_at_install=True)

        assert result == pytest.approx(0.5 * EXECUTION_MULTIPLIER_TRUE)

    def test_runs_code_at_install_false_uses_default_multiplier(self) -> None:
        result = compute_impact("runtime", normalized_fan_out=0.0, transitive_count=0, runs_code_at_install=False)

        assert result == pytest.approx(0.5 * EXECUTION_MULTIPLIER_DEFAULT)

    def test_runs_code_at_install_none_uses_default_multiplier(self) -> None:
        result = compute_impact("runtime", normalized_fan_out=0.0, transitive_count=0, runs_code_at_install=None)

        assert result == pytest.approx(0.5 * EXECUTION_MULTIPLIER_DEFAULT)


# ============================================================================
# combine_incident_probability
# ============================================================================


class TestCombineIncidentProbability:
    def test_both_known_matches_hand_computed_union(self) -> None:
        result = combine_incident_probability(0.4, 0.25)

        assert result == pytest.approx(1.0 - (1.0 - 0.4) * (1.0 - 0.25))

    def test_p_vuln_none_returns_none(self) -> None:
        assert combine_incident_probability(None, 0.25) is None

    def test_p_supplychain_none_returns_none(self) -> None:
        assert combine_incident_probability(0.4, None) is None

    def test_both_none_returns_none(self) -> None:
        assert combine_incident_probability(None, None) is None

    def test_both_zero_is_zero(self) -> None:
        assert combine_incident_probability(0.0, 0.0) == 0.0


# ============================================================================
# compute_expected_exposure
# ============================================================================


class TestComputeExpectedExposure:
    def test_known_inputs_multiply(self) -> None:
        assert compute_expected_exposure(2.0, 0.25) == pytest.approx(0.5)

    def test_p_incident_none_returns_none(self) -> None:
        assert compute_expected_exposure(2.0, None) is None


# ============================================================================
# fitness_projection
# ============================================================================


class TestFitnessProjection:
    def test_zero_exposure_is_full_fitness(self) -> None:
        assert fitness_projection(0.0) == 100

    def test_hand_computed_mid_range_value(self) -> None:
        result = fitness_projection(0.25)

        assert result == round(100 * math.exp(-4.0 * 0.25))

    def test_none_returns_none(self) -> None:
        assert fitness_projection(None) is None

    def test_monotonically_decreasing_as_exposure_increases(self) -> None:
        values = [fitness_projection(x) for x in (0.0, 0.1, 0.5, 1.0, 2.0)]

        assert values == sorted(values, reverse=True)
