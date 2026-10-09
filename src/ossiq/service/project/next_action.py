"""The single next action for a package, as a plain-language label.

Shared by the CLI "What's Next" column, the `info` drift block, and the agent / MCP decision.
Pure: takes a ScanRecord, returns a label or None. Styling (Rich markup for the console,
colour classes for the HTML report) lives in the renderers that consume this.
"""

from ossiq.domain.common import INACTIVE_STATUSES, WIDENING_RUNGS
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
from ossiq.solver.version_matchers import engine_mismatch_reason

CHECK_FOR_THE_FIX = "Check for the Fix"
FIND_ALTERNATIVE = "Find alternative"
CONSIDER_ALTERNATIVE = "Consider alternative"
CHECK_RELEASE_NOTES = "Check Release Notes"
UPDATE_IMMEDIATELY = "Update Immediately"
WAIT_FOR_COOLDOWN = "Wait for cooldown"
CONSTRAINED_CHECK_NEWER = "Constrained. Check newer version"
WITHHELD_BY_STRATEGY = "Withheld by strategy"

# The ladder order, most urgent first — used to pick one headline action out of several.
# CONSTRAINED_CHECK_NEWER sits last: a package you can simply bump outranks one you cannot.
# WITHHELD_BY_STRATEGY sits below it in turn: nothing about the package is holding it back, only
# the tier this run asked for, and a different --update-strategy would move it.
NEXT_ACTION_PRIORITY: tuple[str, ...] = (
    CHECK_FOR_THE_FIX,
    FIND_ALTERNATIVE,
    CONSIDER_ALTERNATIVE,
    CHECK_RELEASE_NOTES,
    UPDATE_IMMEDIATELY,
    WAIT_FOR_COOLDOWN,
    CONSTRAINED_CHECK_NEWER,
    WITHHELD_BY_STRATEGY,
)

AT_LATEST_DIFFS: frozenset[int] = frozenset({VERSION_LATEST, VERSION_DIFF_BUILD, VERSION_DIFF_PRERELEASE})


def has_in_range_upgrade(record: ScanRecord) -> bool:
    """True when the solver found somewhere to move to, inside the declared range.

    A ladder pick that only exists by widening version_constraint (IN_MAJOR/LATEST) does not
    count here — it needs the manifest constraint widened first, so it stays "Constrained" from
    this function's point of view even though recommended_version is populated.
    """
    return (
        record.recommended_version is not None
        and record.recommended_version != record.installed_version
        # Anything not in WIDENING_RUNGS is writable as-is; the None/SOLVER rungs the old
        # WRITABLE_RUNGS set enumerated are already implied by the two conditions above.
        and record.recommended_from_rung not in WIDENING_RUNGS
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
    # The registry itself retired the package, so no bump inside it helps. A deprecated *version* of
    # a live package (uuid@3) is the opposite - updating is the fix - and falls through to the ladder.
    if record.registry_status in INACTIVE_STATUSES:
        return FIND_ALTERNATIVE
    if diff_index in AT_LATEST_DIFFS and state in NOT_MAINTAINED:
        return FIND_ALTERNATIVE
    if state == MaintenanceState.WINDING_DOWN:
        return CONSIDER_ALTERNATIVE
    # Checked below the rules above and above the drift ladder: those describe the package, this
    # describes the bump. An update the user cannot take yet must not be labelled as one they can —
    # that mismatch is what made `status` say "Update Immediately" for a version `apply` refused.
    # OSS IQ's cooldown never holds a package with a CVE or end-of-life motive - select_target
    # escalates past it - but the package manager's release cutoff does, since the installer
    # refuses the release whatever the motive. Waiting is then the only move left besides lifting
    # that cutoff; an exploitable CVE is still headlined by CHECK_FOR_THE_FIX above.
    if record.strategy_selection is not None and record.strategy_selection.cooldown_hold is not None:
        return WAIT_FOR_COOLDOWN
    if diff_index == VERSION_DIFF_MAJOR:
        return CHECK_RELEASE_NOTES
    if diff_index in (VERSION_DIFF_MINOR, VERSION_DIFF_PATCH):
        if has_in_range_upgrade(record):
            return UPDATE_IMMEDIATELY
        # No recommendation and nothing constraining it: the solver simply had no opinion.
        if record.recommended_version is None and not record.version_constraint:
            return UPDATE_IMMEDIATELY
        # The tier refused to move this package, so the declared range is not what is holding it
        # back — scikit-learn 1.8.0 declared `<2.0.0` under `security` has no writable target, but
        # `<2.0.0` admits 1.9.1 perfectly well. Blaming the range there was the defect this label
        # exists to fix; strategy_selection.withheld_reason is set on exactly that branch of
        # select_target, and is None when the tier admitted a motive but nothing was reachable.
        if record.strategy_selection is not None and record.strategy_selection.withheld_reason:
            return WITHHELD_BY_STRATEGY
        # Behind the registry's latest, but the declared range admits no bump to make.
        return CONSTRAINED_CHECK_NEWER
    return None


def needs_attention(record: ScanRecord) -> bool:
    """Whether a transitive package holds something a consumer has to act on or know about.

    Decides which transitives the standard export keeps. Drift doesn't count, and neither does a
    recommendation with nothing behind it but drift: nobody manages a transitive's version directly,
    so being behind is only news alongside a CVE, a conflict, or a release or upstream that is going
    away - and each of those keeps the entry, recommendation included, on its own.
    """
    state = record.maintenance.state if record.maintenance is not None else None
    return (
        bool(record.cve)
        or bool(record.rejected_candidates)
        or bool(record.constraint_conflict)
        or record.is_installed_deprecated
        or record.is_installed_yanked
        or record.is_installed_package_unpublished
        or record.registry_status in INACTIVE_STATUSES
        or state in NOT_MAINTAINED
    )


def engine_mismatch_summary(record: ScanRecord, engine_context: dict[str, str] | None) -> str | None:
    """Explain why record.compatibility.engine_compatible is False, or None when nothing conflicts.

    Lives here rather than in the renderer because the check itself is `solver/`'s, which
    `ui/renderers/` may not import (test_import_boundaries). Deriving it from the one
    reason-returning function also keeps the console text identical to the string the gate already
    wrote into ScanRecord.rejected_candidates, and reports only the engine that actually
    mismatches — a package declaring both `node` and `npm` used to have the satisfied one named
    too.
    """
    return engine_mismatch_reason(record.compatibility.engine_requirement, engine_context or {})
