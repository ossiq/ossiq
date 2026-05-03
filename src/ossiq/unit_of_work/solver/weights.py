from __future__ import annotations

W_ENGINE: int = 1_000_000
W_DEPRECATED: int = 10_000
W_VERY_FRESH: int = 1_000_000
VERY_FRESH_THRESHOLD_DAYS: int = 7
# L5 – CVE hard clause (see encoder.py)
# L6 – very-fresh soft-hard: W_VERY_FRESH penalty for versions published < VERY_FRESH_THRESHOLD_DAYS
# L7 – health score weight: reserved, not implemented.


def age_weight(age_days: int | None) -> int:
    """Freshness bonus weight: max(1, 100_000 - age_days). None -> 1."""
    if age_days is None:
        return 1
    return max(1, 100_000 - age_days)
