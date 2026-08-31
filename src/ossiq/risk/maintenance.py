"""
Maintenance-state model - a small naive-Bayes posterior over four maintenance states.

Replaces the un-calibrated Composite Stability Index. The corridor normalizer from
arXiv:2504.00542 did not transfer to a GitHub sample (see risk/stability.py); this model
instead combines a handful of transparent observations - each validated or near-deterministic -
into P(state | observations), and reports P(abandoned) + P(deprecated) as the "not maintained"
risk that feeds triage:

    P(S | obs) is proportional to P(S) * product over k of P(obs_k | S)

The likelihood tables are hand-tunable constants (the same transparency the TRIANGULAR
corridors had, but typed as probabilities) and are re-fitted from the 4-state corpus in
`qa/calibrate_stability.py`. Observations are dropped when unavailable, so a package with no
GraphQL sample is still scored on the signals that are present.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum


class MaintenanceState(StrEnum):
    """The four states the model discriminates, ordered from healthiest to least."""

    MAINTAINED = "maintained"
    WINDING_DOWN = "winding_down"
    ABANDONED = "abandoned"
    DEPRECATED = "deprecated"


STATES: tuple[str, ...] = tuple(state.value for state in MaintenanceState)

NOT_MAINTAINED: frozenset[str] = frozenset({MaintenanceState.ABANDONED, MaintenanceState.DEPRECATED})
"""States whose combined probability is the "not maintained" risk that feeds triage."""


# --- deprecation evidence --------------------------------------------------------------------


class DeprecationSignal(StrEnum):
    """One reason to believe a package's maintainers have declared it end-of-life."""

    ARCHIVED = "archived"
    """GitHub repository archived flag."""
    REGISTRY_DEPRECATED = "registry_deprecated"
    """npm `deprecated` field set, or every PyPI release yanked."""
    INACTIVE_CLASSIFIER = "inactive_classifier"
    """PyPI trove classifier `Development Status :: 7 - Inactive`."""
    TOPIC_TAGGED = "topic_tagged"
    """GitHub repository topic in DEPRECATION_TOPICS."""
    DESCRIPTION_MARKED = "description_marked"
    """Repository description or registry summary carries a deprecation phrase."""
    README_MARKED = "readme_marked"
    """The top of the README carries a deprecation banner."""
    PINNED_NOTICE = "pinned_notice"
    """A pinned issue titled like a deprecation / migration notice."""
    SUCCESSOR_NAMED = "successor_named"
    """A replacement package is named in the metadata, deprecation message, or README."""


STRONG_SIGNALS: frozenset[DeprecationSignal] = frozenset(
    {
        DeprecationSignal.ARCHIVED,
        DeprecationSignal.REGISTRY_DEPRECATED,
        DeprecationSignal.INACTIVE_CLASSIFIER,
    }
)
"""Near-deterministic markers - any one of these on its own makes the evidence `strong`."""

DEPRECATION_NONE = "none"
DEPRECATION_WEAK = "weak"
DEPRECATION_STRONG = "strong"

INACTIVE_CLASSIFIER = "Development Status :: 7 - Inactive"

DEPRECATION_TOPICS: frozenset[str] = frozenset({"deprecated", "unmaintained", "abandoned", "obsolete", "eol"})

DEPRECATION_PHRASE_RE = re.compile(
    r"deprecat"
    r"|\bno longer (maintained|supported|developed)\b"
    r"|\b(un|not )maintained\b"
    r"|\bthis (project|repo|repository|package|library|module) is (dead|archived|abandoned|unmaintained)\b"
    r"|\bin maintenance mode\b"
    r"|\bend[ -]of[ -]life\b",
    re.IGNORECASE,
)

PINNED_NOTICE_RE = re.compile(
    r"deprecat|\bmigrat|end[ -]of[ -]life|\bsunset|\bno longer\b|\bis dead\b|\bunmaintained\b"
    r"|\bmoved to\b|\bsuccessor\b|use .{0,25} instead",
    re.IGNORECASE,
)

SUCCESSOR_RE = re.compile(
    r"\b(?:use|switch to|migrate to|move to|moved to|replaced by|superseded by|successor is)\s+"
    r"[`'\"]?(@?[A-Za-z][A-Za-z0-9._/-]*[A-Za-z0-9])[`'\"]?"
    r"(?=\s+(?:instead|rather than|going forward|for new|from now)|[`'\".,)]|$)",
    re.IGNORECASE,
)

SUCCESSOR_STOPWORDS = frozenset(
    {"it", "this", "that", "the", "them", "these", "those", "our", "your", "any", "one", "a", "an"}
)


@dataclass(frozen=True)
class DeprecationEvidence:
    """What the collector found, plus a coarse strength tier for the model."""

    signals: frozenset[DeprecationSignal]
    successor: str | None

    @property
    def strength(self) -> str:
        """`none`, `weak` (one soft signal), or `strong` (a STRONG_SIGNAL or two-plus soft ones)."""
        if not self.signals:
            return DEPRECATION_NONE
        if self.signals & STRONG_SIGNALS or len(self.signals) >= 2:
            return DEPRECATION_STRONG
        return DEPRECATION_WEAK


NO_DEPRECATION = DeprecationEvidence(frozenset(), None)


def named_successor(text: str | None) -> str | None:
    """First "use X instead" style replacement package named in `text`, or None.

    Deliberately conservative: the replacement has to be followed by "instead" / "rather than"
    / punctuation, and a bare common English word ("use it instead") is rejected.
    """
    if not text:
        return None
    match = SUCCESSOR_RE.search(text)
    if not match:
        return None
    candidate = match.group(1).rstrip(".,;:)")
    if candidate.lower() in SUCCESSOR_STOPWORDS:
        return None
    return candidate


def deprecation_evidence(
    *,
    archived: bool | None,
    classifiers: Sequence[str],
    all_releases_yanked: bool,
    npm_deprecated: bool,
    deprecation_message: str | None,
    repo_description: str | None,
    summary: str | None,
    topics: Sequence[str],
    readme_head: str | None,
    pinned_titles: Sequence[str],
) -> DeprecationEvidence:
    """Reduce every available deprecation marker to a `DeprecationEvidence`.

    Every argument is optional at the call site (pass the empty / falsy default when a source
    was not fetched). `readme_head` should already be truncated to the first few KB.
    """

    signals: set[DeprecationSignal] = set()
    if archived:
        signals.add(DeprecationSignal.ARCHIVED)
    if npm_deprecated or all_releases_yanked:
        signals.add(DeprecationSignal.REGISTRY_DEPRECATED)
    if any(classifier.strip() == INACTIVE_CLASSIFIER for classifier in classifiers):
        signals.add(DeprecationSignal.INACTIVE_CLASSIFIER)
    if {topic.lower() for topic in topics} & DEPRECATION_TOPICS:
        signals.add(DeprecationSignal.TOPIC_TAGGED)
    if any(text and DEPRECATION_PHRASE_RE.search(text) for text in (repo_description, summary)):
        signals.add(DeprecationSignal.DESCRIPTION_MARKED)
    if readme_head and DEPRECATION_PHRASE_RE.search(readme_head):
        signals.add(DeprecationSignal.README_MARKED)
    if any(PINNED_NOTICE_RE.search(title) for title in pinned_titles):
        signals.add(DeprecationSignal.PINNED_NOTICE)

    # A named successor is only trusted from an npm deprecation message (inherently a
    # deprecation context) or from prose that *also* carries a deprecation phrase - a bare
    # "migrate to X" in a README is usually a tutorial, not an end-of-life notice.
    successor = named_successor(deprecation_message)
    for text in (readme_head, repo_description, summary):
        if text and DEPRECATION_PHRASE_RE.search(text):
            successor = successor or named_successor(text)
    if successor:
        signals.add(DeprecationSignal.SUCCESSOR_NAMED)

    return DeprecationEvidence(frozenset(signals), successor)


# --- naive-Bayes maintenance model ----------------------------------------------------------


PRIORS: dict[str, float] = {
    MaintenanceState.MAINTAINED: 0.44,
    MaintenanceState.WINDING_DOWN: 0.30,
    MaintenanceState.ABANDONED: 0.16,
    MaintenanceState.DEPRECATED: 0.10,
}
"""Base rates. Fit from the 62-repo CORPUS in qa/calibrate_stability.py (26/15/11/10) with a
mild lean back toward `maintained` - the corpus over-samples dead repos by design. `winding_down`
is bumped over its raw share so a quiet-but-not-dead mature library isn't pinned to abandoned."""

LIKELIHOOD: dict[str, dict[object, dict[str, float]]] = {
    "deprecation_strength": {
        DEPRECATION_NONE: {"maintained": 0.95, "winding_down": 0.93, "abandoned": 0.78, "deprecated": 0.05},
        DEPRECATION_WEAK: {"maintained": 0.04, "winding_down": 0.08, "abandoned": 0.13, "deprecated": 0.25},
        DEPRECATION_STRONG: {"maintained": 0.01, "winding_down": 0.02, "abandoned": 0.07, "deprecated": 0.70},
    },
    "has_stopped": {
        # True is NOT diagnostic of abandonment on its own - a winding_down library goes silent
        # for 3-18 months between touches by definition. It only says "not in an active commit
        # streak"; push_age + deprecation_strength do the abandoned/winding_down split.
        True: {"maintained": 0.03, "winding_down": 0.42, "abandoned": 0.93, "deprecated": 0.85},
        False: {"maintained": 0.97, "winding_down": 0.78, "abandoned": 0.05, "deprecated": 0.15},
    },
    "push_age": {
        # fresh (<30d): a push this recent is near-decisive for "active" - the strongest single
        # recency signal, split out from `recent` so release-driven low-churn repos (werkzeug,
        # sqlalchemy) can't drift toward winding_down on commit dispersion alone.
        "fresh": {"maintained": 0.93, "winding_down": 0.12, "abandoned": 0.01, "deprecated": 0.02},
        # recent (30-90d): a maintained project rarely lets its repo sit 1-3 months untouched;
        # in the corpus every `recent` repo (pytz, distlib, mccabe) is winding_down.
        "recent": {"maintained": 0.18, "winding_down": 0.60, "abandoned": 0.06, "deprecated": 0.10},
        # aging (90-365d): WINDING_DOWN PEAKS HERE
        "aging": {"maintained": 0.09, "winding_down": 0.68, "abandoned": 0.20, "deprecated": 0.20},
        # stale (365-730d): genuinely split - a finished library (jinja, itsdangerous) and a
        # dead one (browserify, django-celery) both land here; leans abandoned but not decisively.
        "stale": {"maintained": 0.02, "winding_down": 0.28, "abandoned": 0.45, "deprecated": 0.36},
        "ancient": {"maintained": 0.01, "winding_down": 0.06, "abandoned": 0.37, "deprecated": 0.36},
    },
    "flow_trend": {
        "improving": {"maintained": 0.45, "winding_down": 0.20, "abandoned": 0.05, "deprecated": 0.05},
        "stable": {"maintained": 0.40, "winding_down": 0.34, "abandoned": 0.13, "deprecated": 0.18},
        # declining engagement is winding_down's *signature*, not just an abandonment tell - the
        # three states share it almost evenly.
        "declining": {"maintained": 0.11, "winding_down": 0.70, "abandoned": 0.72, "deprecated": 0.66},
    },
}

MAINTENANCE_THRESHOLD = 0.5
"""P(abandoned) + P(deprecated) at or above this marks the package unstable for triage."""

OBSERVATION_COUNT = len(LIKELIHOOD)
"""How many observation types the model can consume - the denominator for `coverage`."""

PUSH_AGE_FRESH_DAYS = 30
PUSH_AGE_RECENT_DAYS = 90
PUSH_AGE_AGING_DAYS = 365
PUSH_AGE_STALE_DAYS = 730


def push_age_bucket(days_since_push: int | None) -> str | None:
    """Discretize `days_since_push` into the model's push-age observation, or None if unknown."""
    if days_since_push is None:
        return None
    if days_since_push < PUSH_AGE_FRESH_DAYS:
        return "fresh"
    if days_since_push < PUSH_AGE_RECENT_DAYS:
        return "recent"
    if days_since_push < PUSH_AGE_AGING_DAYS:
        return "aging"
    if days_since_push < PUSH_AGE_STALE_DAYS:
        return "stale"
    return "ancient"


@dataclass(frozen=True)
class MaintenanceAssessment:
    """The model's verdict for one package's upstream repository."""

    posterior: dict[str, float]
    """State -> probability, sums to 1."""

    state: str
    """The most probable state (argmax of `posterior`)."""

    p_not_maintained: float
    """posterior[abandoned] + posterior[deprecated] - the risk that feeds triage."""

    observations: dict[str, object]
    """The non-None observations that fed the posterior, for surfacing and calibration."""

    @property
    def p_maintained(self) -> float:
        return 1.0 - self.p_not_maintained


def maintenance_posterior(observations: Mapping[str, object]) -> dict[str, float]:
    """Normalized P(state | observations). Unknown observation names / values are ignored."""

    scores = dict(PRIORS)
    for name, value in observations.items():
        table = LIKELIHOOD.get(name)
        if table is None or value is None:
            continue
        row = table.get(value)
        if row is None:
            continue
        scores = {state: scores[state] * row[state] for state in scores}
    total = sum(scores.values())
    if total == 0:
        return dict(PRIORS)
    return {state: score / total for state, score in scores.items()}


def gated_observations(
    *,
    deprecation_strength: str | None,
    has_stopped: bool | None,
    push_age: str | None,
    flow_trend: str | None,
) -> dict[str, object]:
    """Apply the two naive-Bayes independence gates and return the observation dict.

    The commit-derived signals are correlated, which naive-Bayes assumes away. Two conditionals
    keep it honest - and both the real scan path and `qa/calibrate_stability.py` route through
    here so the calibrated numbers match what ships:

    - a `strong` deprecation marker (archived / registry-deprecated / inactive classifier) is
      near-deterministic - an archived repo with recent CI commits is still deprecated - so every
      commit-recency observation is dropped and only the deprecation signal feeds the model.
    - `flow_trend` is release-driven noise on a repo that pushed in the last 30 days; it only
      carries a maintenance signal once the commit activity itself has slowed.
    """
    if deprecation_strength == DEPRECATION_STRONG:
        return {"deprecation_strength": DEPRECATION_STRONG}
    return {
        "deprecation_strength": deprecation_strength,
        "has_stopped": has_stopped,
        "push_age": push_age,
        "flow_trend": flow_trend if push_age != "fresh" else None,
    }


def assess_maintenance(observations: Mapping[str, object]) -> MaintenanceAssessment | None:
    """Full assessment, or None when not one observation is available."""

    present = {name: value for name, value in observations.items() if value is not None}
    if not present:
        return None
    posterior = maintenance_posterior(present)
    state = max(posterior, key=posterior.__getitem__)
    p_not_maintained = sum(posterior[s] for s in NOT_MAINTAINED)
    return MaintenanceAssessment(posterior, state, p_not_maintained, present)
