"""The single next action for a package, as a plain-language label.

Shared by the CLI "What's Next" column, the `info` drift block, and the agent / MCP decision.
Pure: takes a ScanRecord, returns a label or None. Styling (Rich markup for the console,
colour classes for the HTML report) lives in the renderers that consume this.
"""

from ossiq.domain.common import RecommendationRung
from ossiq.domain.version import (
    VERSION_DIFF_BUILD,
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_DIFF_PRERELEASE,
    VERSION_LATEST,
)
from ossiq.risk.maintenance import NOT_MAINTAINED, MaintenanceState
from ossiq.risk.triage import EPSS_EXPLOIT_THRESHOLD
from ossiq.service.project.models import ScanRecord

CHECK_FOR_THE_FIX = "Check for the Fix"
FIND_ALTERNATIVE = "Find alternative"
CONSIDER_ALTERNATIVE = "Consider alternative"
CHECK_RELEASE_NOTES = "Check Release Notes"
UPDATE_IMMEDIATELY = "Update Immediately"
CONSTRAINED_CHECK_NEWER = "Constrained. Check newer version"

# The ladder order, most urgent first — used to pick one headline action out of several.
# CONSTRAINED_CHECK_NEWER sits last: a package you can simply bump outranks one you cannot.
NEXT_ACTION_PRIORITY: tuple[str, ...] = (
    CHECK_FOR_THE_FIX,
    FIND_ALTERNATIVE,
    CONSIDER_ALTERNATIVE,
    CHECK_RELEASE_NOTES,
    UPDATE_IMMEDIATELY,
    CONSTRAINED_CHECK_NEWER,
)

AT_LATEST_DIFFS: frozenset[int] = frozenset({VERSION_LATEST, VERSION_DIFF_BUILD, VERSION_DIFF_PRERELEASE})

# Rungs that sit inside the declared version_constraint — the writers can apply these directly.
# IN_MAJOR/LATEST require widening the constraint first, so a package only reachable there is
# still "Constrained" from this ladder's point of view, matching the console/agent wording that
# predates the version-ladder fallback.
WRITABLE_RUNGS: frozenset[RecommendationRung | None] = frozenset(
    {None, RecommendationRung.SOLVER, RecommendationRung.IN_RANGE}
)


def has_in_range_upgrade(record: ScanRecord) -> bool:
    """True when the solver found somewhere to move to, inside the declared range.

    A ladder pick that only exists by widening version_constraint (IN_MAJOR/LATEST) does not
    count here — it needs the manifest constraint widened first, so it stays "Constrained" from
    this function's point of view even though recommended_version is populated.
    """
    return (
        record.recommended_version is not None
        and record.recommended_version != record.installed_version
        and record.recommended_from_rung in WRITABLE_RUNGS
    )


def next_action_label(record: ScanRecord) -> str | None:
    """The single next action for a package, or None when nothing is due.

    First match wins: an exploitable CVE outranks a dying upstream, which outranks version drift.
    """
    # ponytail: flat rule ladder on purpose - the product owner extends it rule by rule.
    diff_index = record.versions_diff_index.diff_index
    state = record.maintenance.state if record.maintenance is not None else None

    has_active_cve = bool(record.cve) and record.epss is not None and record.epss >= EPSS_EXPLOIT_THRESHOLD
    if has_active_cve:
        return CHECK_FOR_THE_FIX
    if diff_index in AT_LATEST_DIFFS and state in NOT_MAINTAINED:
        return FIND_ALTERNATIVE
    if state == MaintenanceState.WINDING_DOWN:
        return CONSIDER_ALTERNATIVE
    if diff_index == VERSION_DIFF_MAJOR:
        return CHECK_RELEASE_NOTES
    if diff_index in (VERSION_DIFF_MINOR, VERSION_DIFF_PATCH):
        if has_in_range_upgrade(record):
            return UPDATE_IMMEDIATELY
        # No recommendation and nothing constraining it: the solver simply had no opinion.
        if record.recommended_version is None and not record.version_constraint:
            return UPDATE_IMMEDIATELY
        # Behind the registry's latest, but the declared range admits no bump to make.
        return CONSTRAINED_CHECK_NEWER
    return None
