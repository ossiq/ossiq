from __future__ import annotations

W_ENGINE: int = 100_000
W_DEPRECATED: int = 10_000
W_VERY_FRESH: int = 100_000
VERY_FRESH_THRESHOLD_DAYS: int = 7

AGE_TIERS: tuple[tuple[int, int], ...] = (
    (30, 80_000),  # < 30 days
    (90, 60_000),  # 30–90 days
    (365, 40_000),  # 90 days – 1 year
    (1095, 10_000),  # 1–3 years
)
AGE_WEIGHT_OLD: int = 1_000  # 3+ years


def age_weight(age_days: int | None) -> int:
    """Freshness bonus weight, bucketed into 5 tiers. None (unknown age) -> minimum tier."""
    if age_days is None:
        return AGE_WEIGHT_OLD
    for threshold, weight in AGE_TIERS:
        if age_days < threshold:
            return weight
    return AGE_WEIGHT_OLD
