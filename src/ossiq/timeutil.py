"""
Collection of utility functions to work with time.
"""

import re
from datetime import UTC, datetime, timedelta


def parse_relative_time_delta(time_unit_str: str, units_supported=("y", "m", "w", "d", "h")) -> timedelta:
    # 1. Match the pattern
    pattern = rf"^(\d+)([{''.join(units_supported)}])?$"
    match = re.match(pattern, time_unit_str)

    if not match:
        raise ValueError(f"Invalid format: {time_unit_str}. Expected <number>[unit]")

    value_str, unit = match.groups()
    value = int(value_str)
    unit = unit or "d"  # Default to days

    # 2. Map units to timedelta constructor arguments
    # We convert everything to days or hours to keep it simple
    unit_map = {
        "y": {"days": value * 365},
        "m": {"days": value * 30},
        "w": {"weeks": value},
        "d": {"days": value},
        "h": {"hours": value},
    }

    # 3. Unpack the dictionary into the timedelta constructor
    return timedelta(**unit_map[unit])


def format_time_days(duration_days: int) -> str:
    """
    Formats a number of days into a human-readable string (e.g., "2y", "1y", "8m", "3w", "5d").
    """
    formatted_string = ""
    if duration_days >= 365:
        years = round(duration_days / 365)
        formatted_string = f"{years}y"
    elif duration_days >= 30:
        months = round(duration_days / 30)
        formatted_string = f"{months}m"
    elif duration_days >= 7:
        weeks = round(duration_days / 7)
        formatted_string = f"{weeks}w"
    else:
        formatted_string = f"{duration_days}d"

    return formatted_string


def parse_iso_datetime(datetime_str: str | None) -> datetime | None:
    """Parse an ISO 8601 string to a tz-aware datetime, or None."""
    if datetime_str:
        return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))
    return None


def age_days_from_iso(published_date_iso: str | None, *, now: datetime | None = None) -> int | None:
    """Days elapsed since published_date_iso. None when date is absent.

    `now` is injectable for deterministic tests; defaults to datetime.now(UTC).
    """
    dt = parse_iso_datetime(published_date_iso)
    if dt is None:
        return None
    _now = now if now is not None else (datetime.now(tz=UTC) if dt.tzinfo else datetime.now())  # noqa: DTZ005
    return (_now - dt).days
