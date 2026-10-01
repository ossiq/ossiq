"""
Utils related to package managers
"""

import re
from datetime import datetime, timedelta

from cel import Context, evaluate
from packaging.specifiers import SpecifierSet
from packaging.version import Version

DATE_ONLY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
ISO_SPAN_RE = re.compile(
    r"P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", re.IGNORECASE
)


def find_lockfile_parser(
    supported_versions,
    options: dict,
) -> str | None:
    """
    Find and return lockfile parser instance: suppose to be one of
    instances of this class, dedicated to a specific schema version.

    Parser could be reused across different schema versions if
    schema change is not relevant to the information needed.
    """
    context = Context(options)

    for version_condition, version_handler in supported_versions.items():
        if evaluate(version_condition, context):
            return version_handler

    return None


def extract_min_python_version(requires_python: str) -> str | None:
    """Return 'X.Y' for the minimum Python declared in a requires-python specifier.

    Parses >= / ~= / == operators to find the lowest declared lower bound.
    Returns None when the specifier is unparseable or has no lower bound.
    """

    try:
        bounds = [Version(s.version) for s in SpecifierSet(requires_python) if s.operator in (">=", "~=", "==")]
        if bounds:
            m = min(bounds)
            return f"{m.major}.{m.minor}"
    except ValueError:
        pass
    return None


def parse_exclude_newer(value: object, *, now: datetime) -> datetime | None:
    """Resolve an `exclude-newer`-style setting to the instant it cuts releases off at.

    Accepts the three forms uv writes: an RFC 3339 timestamp, a bare `YYYY-MM-DD` date (read as
    the end of that day in the local time zone, as uv does), and an ISO 8601 span such as `P7D`
    (meaning `now` minus the span). uv's friendlier spans ("7 days") are not parsed here. The
    lockfile records them normalized to ISO, so callers fall back to that.

    Args:
        value: The raw TOML/env value.
        now: The instant a span counts back from.

    Returns:
        The cutoff as a tz-aware datetime, or None when `value` is none of the forms above.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if span_match := ISO_SPAN_RE.fullmatch(text):
        years, months, weeks, days, hours, minutes, seconds = (int(g or 0) for g in span_match.groups())
        if not any((years, months, weeks, days, hours, minutes, seconds)):
            return None
        # Calendar units are rounded up (366/31 days) so a span never admits a release uv rejects.
        span = timedelta(
            days=years * 366 + months * 31 + weeks * 7 + days, hours=hours, minutes=minutes, seconds=seconds
        )
        return now - span
    if DATE_ONLY_RE.fullmatch(text):
        return (datetime.fromisoformat(text) + timedelta(days=1)).astimezone()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.astimezone()
