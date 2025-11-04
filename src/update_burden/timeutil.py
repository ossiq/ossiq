"""
Collection of utility functions to work with time.
"""
import re
import pandas as pd


def parse_relative_time_delta(
        time_unit_str: str,
        units_supported=("y", "m", "w", "d", "h")) -> pd.Timedelta:
    """
    It also allows for a single number without a unit, which will default to days.
    """

    pattern = r"^(\d+)([" + "".join(units_supported) + r"])?$"
    matched_pattern = re.match(pattern, time_unit_str)
    if matched_pattern:
        time_value, unit = matched_pattern.groups()
        time_unit_str = f"{time_value}{unit if unit else "d"}"

        time_value = int(time_value)

        # FIXME: refactor this to calculate exact time delta
        if unit == "y":
            return pd.Timedelta(days=time_value * 365)  # Approximate years
        elif unit == "m":
            return pd.Timedelta(days=time_value * 30)  # Approximate months
        elif unit == "w":
            return pd.Timedelta(weeks=time_value)
        elif unit == "d":
            return pd.Timedelta(days=time_value)
        elif unit == "h":
            return pd.Timedelta(hours=time_value)

    raise ValueError(
        f"Invalid time delta format: {time_unit_str}. "
        f"Expected format: <number><unit>, where unit is one of {", ".join(units_supported)}. "
        "Example: 1y, 6m, 2w, 30d, 24h."
    )
