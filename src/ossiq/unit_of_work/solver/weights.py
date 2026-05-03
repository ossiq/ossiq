from __future__ import annotations

W_ENGINE: int = 1_000_000
W_DEPRECATED: int = 10_000
# L5 – health score weight: reserved, not implemented.


def age_weight(age_days: int | None) -> int:
    """Freshness bonus weight: max(1, 100_000 - age_days). None -> 1."""
    if age_days is None:
        return 1
    return max(1, 100_000 - age_days)
