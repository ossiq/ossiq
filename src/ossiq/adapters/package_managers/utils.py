"""
Utils related to package managers
"""

import re
from datetime import datetime, timedelta

from cel import Context, evaluate
from packaging.specifiers import SpecifierSet
from packaging.version import Version

DATE_ONLY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
# uv resolves spans to a fixed number of seconds and rejects calendar units, so neither pattern
# admits years or months: a value uv drops must not become a cutoff here either.
ISO_SPAN_RE = re.compile(r"P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", re.IGNORECASE)
FRIENDLY_SPAN_TERM_RE = re.compile(r"(\d+)\s*([a-z]+)")
FRIENDLY_SPAN_RE = re.compile(r"\d+\s*[a-z]+(?:[\s,]*\d+\s*[a-z]+)*")
FRIENDLY_SPAN_UNITS: dict[str, timedelta] = {
    **dict.fromkeys(("w", "wk", "wks", "week", "weeks"), timedelta(weeks=1)),
    **dict.fromkeys(("d", "day", "days"), timedelta(days=1)),
    **dict.fromkeys(("h", "hr", "hrs", "hour", "hours"), timedelta(hours=1)),
    **dict.fromkeys(("m", "min", "mins", "minute", "minutes"), timedelta(minutes=1)),
    **dict.fromkeys(("s", "sec", "secs", "second", "seconds"), timedelta(seconds=1)),
}


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


def parse_friendly_span(text: str) -> timedelta | None:
    """Parse a span in uv's "friendly" form, e.g. "1 week", "24h", "2 days, 3 hours" or "1d12h".

    Units are lowercase and whole, as uv accepts them; "ago", fractions and calendar units make the
    whole value unreadable, the same as uv, which then applies no cutoff.
    """
    if not FRIENDLY_SPAN_RE.fullmatch(text):
        return None
    total = timedelta()
    for count, unit in FRIENDLY_SPAN_TERM_RE.findall(text):
        if unit not in FRIENDLY_SPAN_UNITS:
            return None
        total += int(count) * FRIENDLY_SPAN_UNITS[unit]
    return total or None


def parse_exclude_newer(value: object, *, now: datetime) -> datetime | None:
    """Resolve an `exclude-newer`-style setting to the instant it cuts releases off at.

    Accepts every form uv does: an RFC 3339 timestamp, a bare `YYYY-MM-DD` date (read as the end of
    that day in the local time zone, as uv does), and a span counted back from `now`, either ISO
    8601 (`P7D`, `PT24H`) or friendly ("7 days", "1w 2d").

    Args:
        value: The raw TOML/env value.
        now: The instant a span counts back from.

    Returns:
        The cutoff as a tz-aware datetime, or None when `value` is none of the forms above — which
        is also what uv makes of it: no cutoff.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if span_match := ISO_SPAN_RE.fullmatch(text):
        weeks, days, hours, minutes, seconds = (int(g or 0) for g in span_match.groups())
        span = timedelta(weeks=weeks, days=days, hours=hours, minutes=minutes, seconds=seconds)
        return now - span if span else None
    if (friendly := parse_friendly_span(text)) is not None:
        return now - friendly
    if DATE_ONLY_RE.fullmatch(text):
        return (datetime.fromisoformat(text) + timedelta(days=1)).astimezone()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.astimezone()
