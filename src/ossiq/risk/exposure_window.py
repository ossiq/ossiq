"""Estimate a dependency's Exposure Window for the Health Score.

The Exposure Window is the number of days an installed dependency is expected
to remain exposed if remediation becomes necessary today. It gives the Health
Score's known-vulnerability model a time horizon: the resulting ``P_vuln`` is
later combined with supply-chain risk and impact to produce Expected Exposure
and the user-facing Fitness projection.

This module owns only the pure, package-level estimate. Scan integration,
probability calculations, aggregation, and presentation belong to later stages
of the Health Score pipeline.
"""

import math

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.version import (
    VERSION_DIFF_BUILD,
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_DIFF_PRERELEASE,
    VERSION_LATEST,
    VersionsDifference,
)

UPGRADE_BASE_DAYS = 30.0

SEMVER_DISTANCE = {
    VERSION_LATEST: 0.0,
    VERSION_DIFF_PATCH: 0.15,
    VERSION_DIFF_PRERELEASE: 0.15,
    VERSION_DIFF_BUILD: 0.15,
    VERSION_DIFF_MINOR: 0.45,
    VERSION_DIFF_MAJOR: 1.0,
}

ECOSYSTEM_FIX_PRIOR = {
    ProjectPackagesRegistry.PYPI: (30.0, 90.0),
    ProjectPackagesRegistry.NPM: (14.0, 60.0),
}


def compute_exposure_window(
    registry: ProjectPackagesRegistry,
    releases_lag: int | None,
    versions_diff_index: VersionsDifference,
) -> float | None:
    """Return the estimated number of days needed to remediate a dependency.

    The estimate combines an ecosystem-specific patch-latency prior with the
    additional upgrade effort implied by semantic-version distance and the
    number of intervening releases.

    It is not a measure of dependency age or vulnerability severity;
    """
    if releases_lag is None or releases_lag < 0:
        return None

    coefficient = SEMVER_DISTANCE.get(versions_diff_index.diff_index)
    if coefficient is None:
        return None

    ecosystem_prior = ECOSYSTEM_FIX_PRIOR.get(registry)
    if ecosystem_prior is None:
        return None

    distance = coefficient * (1.0 + math.log1p(releases_lag))
    upgrade_distance_days = UPGRADE_BASE_DAYS * distance
    median_fix_days, tail_fix_days = ecosystem_prior
    expected_patch_latency = 0.5 * median_fix_days + 0.5 * tail_fix_days

    return expected_patch_latency + upgrade_distance_days
