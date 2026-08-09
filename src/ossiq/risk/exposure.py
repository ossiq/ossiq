"""
Impact, incident probability, expected exposure, and fitness for the Health Score
"""

import math
from typing import Literal

DependencyTier = Literal["runtime", "build", "dev"]

TIER_MULTIPLIER: dict[DependencyTier, float] = {"runtime": 1.0, "build": 0.7, "dev": 0.3}
EXECUTION_MULTIPLIER_TRUE = 1.3
EXECUTION_MULTIPLIER_DEFAULT = 1.0
REACH_LOG_WEIGHT = 0.05
FITNESS_DECAY_RATE = 4.0


def compute_impact(
    tier: DependencyTier,
    normalized_fan_out: float,
    transitive_count: int,
    runs_code_at_install: bool | None,
    reach_log_weight: float = REACH_LOG_WEIGHT,
    exec_multiplier_true: float = EXECUTION_MULTIPLIER_TRUE,
    exec_multiplier_default: float = EXECUTION_MULTIPLIER_DEFAULT,
) -> float:
    """Return blast-radius impact"""

    fan_out = max(0.0, min(normalized_fan_out, 1.0))
    count = max(transitive_count, 0)

    tier_multiplier = TIER_MULTIPLIER[tier]
    fan_multiplier = 0.5 + 0.5 * fan_out

    execution_multiplier = exec_multiplier_default
    # postinstall penalty
    if runs_code_at_install:
        execution_multiplier = exec_multiplier_true

    reach_multiplier = 1.0 + reach_log_weight * math.log1p(count)

    return tier_multiplier * fan_multiplier * execution_multiplier * reach_multiplier


def combine_incident_probability(
    p_vuln: float | None,
    p_supplychain: float | None,
) -> float | None:
    """Union the two hazard channels"""

    # Both channels are unknown
    if p_vuln is None or p_supplychain is None:
        return None

    # P(incident) = 1 - P(NO vuln incident) * P(NO supply-chain incident)
    return 1.0 - (1.0 - p_vuln) * (1.0 - p_supplychain)


def compute_expected_exposure(
    impact: float,
    p_incident: float | None,
) -> float | None:
    if p_incident is None:
        return None

    return impact * p_incident


def fitness_projection(
    expected_exposure: float | None,
    fitness_decay_rate: float = FITNESS_DECAY_RATE,
) -> int | None:
    if expected_exposure is None:
        return None

    return round(100 * math.exp(-fitness_decay_rate * expected_exposure))
