from __future__ import annotations

W_ENGINE: int = 100_000
W_DEPRECATED: int = 10_000
W_VERY_FRESH: int = 100_000
VERY_FRESH_THRESHOLD_DAYS: int = 7

# L3: semver-rank-based preference weights.
# Rank 0 = highest eligible semver within constraint. Each step down reduces weight by
# SEMVER_RANK_STEP so that a W_DEPRECATED (10 000) penalty can override an adjacent rank
# without requiring age information. Floor is SEMVER_RANK_WEIGHT_MIN.
SEMVER_RANK_WEIGHT_BASE: int = 80_000
SEMVER_RANK_STEP: int = 5_000
SEMVER_RANK_WEIGHT_MIN: int = 1_000


def semver_rank_weight(rank: int) -> int:
    """L3 preference weight from semver rank (0 = latest eligible semver).

    Each rank step reduces weight by SEMVER_RANK_STEP so soft penalties (deprecated,
    engine mismatch) can override adjacent-rank candidates without relying on age.
    """
    return max(SEMVER_RANK_WEIGHT_BASE - rank * SEMVER_RANK_STEP, SEMVER_RANK_WEIGHT_MIN)
