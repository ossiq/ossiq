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
"""Base rates. Fit from the 63-repo CORPUS in qa/calibrate_stability.py (26/15/12/10) with a
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
        # fresh (<45d): a push this recent is near-decisive for "active" - the strongest single
        # recency signal, split out from `recent` so release-driven low-churn repos (werkzeug,
        # sqlalchemy) can't drift toward winding_down on commit dispersion alone.
        "fresh": {"maintained": 0.93, "winding_down": 0.12, "abandoned": 0.01, "deprecated": 0.02},
        # recent (45-90d): a six-week to three-month gap between pushes. The old row put this at
        # 0.18/0.60 on the strength of three dormant PyPI repos (pytz, distlib, mccabe), which
        # made the bucket decide the verdict by itself - `fuse.js`, 42 days since its last push
        # and a release six weeks earlier, came out winding_down at P=0.92 with every other
        # observation neutral or positive. On npm a six-week quiet spell is ordinary for a mature
        # library, so the row is now barely directional and the release-cadence and flow
        # observations do the work of separating a lull from a wind-down.
        "recent": {"maintained": 0.45, "winding_down": 0.40, "abandoned": 0.08, "deprecated": 0.10},
        # aging (90-365d): WINDING_DOWN PEAKS HERE
        "aging": {"maintained": 0.09, "winding_down": 0.68, "abandoned": 0.20, "deprecated": 0.20},
        # stale (365-730d): genuinely split - a finished library (jinja, itsdangerous) and a
        # dead one (browserify, django-celery) both land here; leans abandoned but not decisively.
        "stale": {"maintained": 0.02, "winding_down": 0.28, "abandoned": 0.45, "deprecated": 0.36},
        "ancient": {"maintained": 0.01, "winding_down": 0.06, "abandoned": 0.37, "deprecated": 0.36},
    },
    "flow_trend": {
        # `improving` and `declining` are fitted from the corpus (see the counts below); `stable`
        # and the abandoned / deprecated columns are not, because a repo dead enough to be labelled
        # either has no issue or PR movement left to measure - 21 of the 22 abandoned/deprecated
        # entries report no flow_trend at all. Those cells are left at their hand-set values and
        # should not be read as calibrated.
        #
        # Corpus flow_trend among repos where it is measured:
        #   maintained   (n=26): improving 13, stable 8, declining 5
        #   winding_down (n=10): improving  5, stable 0, declining 5
        # A healthy project declining on issue/PR flow is ordinary - it usually means the project
        # got popular faster than the maintainers grew. The table below is that ratio blended
        # halfway back toward the previous hand-set row, because n=10 is thin.
        "improving": {"maintained": 0.47, "winding_down": 0.33, "abandoned": 0.05, "deprecated": 0.05},
        "stable": {"maintained": 0.40, "winding_down": 0.34, "abandoned": 0.13, "deprecated": 0.18},
        # Was 0.11 : 0.70, a 6.4x tilt the corpus never supported (it measures 1 : 2.6). At that
        # strength one noisy directional signal decided the verdict on its own, which is how a
        # package that had shipped six weeks earlier came out winding_down at P=0.92.
        "declining": {"maintained": 0.22, "winding_down": 0.55, "abandoned": 0.72, "deprecated": 0.66},
    },
    "release_age": {
        # How long since the registry last saw a release. The push observations describe the
        # repository; this one describes what actually reached users, and a package can be quiet
        # on one clock while alive on the other - which is the case the model had no way to see.
        #
        # Only two of the four columns are fitted, and the corpus cannot currently fix the other
        # two - counting rows where `gated_observations` actually admits this observation:
        #   maintained   (n= 0)
        #   winding_down (n=10): current 1, recent 3, stale 3, ancient 3
        #   abandoned    (n=10): current 0, recent 0, stale 1, ancient 9
        #   deprecated   (n= 0)
        # Every maintained repo in the corpus pushed inside PUSH_AGE_FRESH_DAYS, so the fresh gate
        # drops release_age before the model sees it; every deprecated one carries a strong marker,
        # which drops everything else. Fitting those two columns from the ungated counts would be
        # fitting on rows this observation never reads. They are set by reasoning instead and are
        # marked as such: a package that has not pushed in six weeks but shipped last month is
        # almost always one that releases on a slow cadence, and the deprecated column is
        # near-unreachable in practice. Closing the gap needs corpus entries that are alive but
        # slow-pushing - see qa/manual/stability-calibrate.md.
        #
        # What the fitted half says: no release in two years favours abandoned over winding_down
        # about 2.4 to 1, while one to two years leans the other way. That is the distinction the
        # model had no way to draw before - `six` (stale, still answering) and `nose` (ancient,
        # gone) look identical on push age alone.
        "current": {"maintained": 0.55, "winding_down": 0.14, "abandoned": 0.07, "deprecated": 0.07},
        "recent": {"maintained": 0.30, "winding_down": 0.29, "abandoned": 0.07, "deprecated": 0.10},
        "stale": {"maintained": 0.10, "winding_down": 0.29, "abandoned": 0.14, "deprecated": 0.13},
        "ancient": {"maintained": 0.05, "winding_down": 0.29, "abandoned": 0.71, "deprecated": 0.70},
    },
}

MAINTENANCE_THRESHOLD = 0.5
"""P(abandoned) + P(deprecated) at or above this marks the package unstable for triage."""

OBSERVATION_COUNT = len(LIKELIHOOD)
"""How many observation types the model can consume - the denominator for `coverage`."""

PUSH_AGE_FRESH_DAYS = 45
"""Widened from 30: at 30 the `fresh`/`recent` boundary was a cliff, not a gradient - one day of
wall-clock moved the posterior from maintained 0.94 to winding_down 0.92, because crossing it
both swapped the push_age row and switched the gated flow_trend penalty on. Six weeks is the
point where an npm library's quiet spell stops being ordinary."""

PUSH_AGE_RECENT_DAYS = 90
PUSH_AGE_AGING_DAYS = 365
PUSH_AGE_STALE_DAYS = 730

RELEASE_AGE_CURRENT_DAYS = 90
RELEASE_AGE_RECENT_DAYS = 365
RELEASE_AGE_STALE_DAYS = 730


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


def release_age_bucket(days_since_release: int | None) -> str | None:
    """Discretize the age of the latest published release, or None when the registry had no date.

    Deliberately coarser than `push_age_bucket`: release cadence is the slower of the two clocks,
    and a library that ships twice a year is not drifting.
    """
    if days_since_release is None:
        return None
    if days_since_release < RELEASE_AGE_CURRENT_DAYS:
        return "current"
    if days_since_release < RELEASE_AGE_RECENT_DAYS:
        return "recent"
    if days_since_release < RELEASE_AGE_STALE_DAYS:
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
    release_age: str | None = None,
) -> dict[str, object]:
    """Apply the naive-Bayes independence gates and return the observation dict.

    The activity-derived signals are correlated, which naive-Bayes assumes away. Three
    conditionals keep it honest - and both the real scan path and `qa/calibrate_stability.py`
    route through here so the calibrated numbers match what ships:

    - a `strong` deprecation marker (archived / registry-deprecated / inactive classifier) is
      near-deterministic - an archived repo with recent CI commits is still deprecated - so every
      activity observation is dropped and only the deprecation signal feeds the model.
    - `flow_trend` is release-driven noise on a repo that pushed in the last PUSH_AGE_FRESH_DAYS;
      it only carries a maintenance signal once the commit activity itself has slowed.
    - `release_age` is dropped on that same fresh repo, for the opposite reason: the push already
      proved the project is being worked on, and letting a recent release say so again would
      count one fact twice. Where it is not dropped is exactly where it earns its keep - a
      library that ships on a slow cadence without much repo churn between releases.

    Args:
        deprecation_strength: `none` / `weak` / `strong`, or None when nothing was checked.
        has_stopped: Whether the commit stream is in an unusually long silence.
        push_age: Bucket from `push_age_bucket`.
        flow_trend: `improving` / `stable` / `declining`, or None without a GraphQL sample.
        release_age: Bucket from `release_age_bucket`, or None when no release date is known.

    Returns:
        Observation name -> value, with None left in place for the model to drop.
    """
    if deprecation_strength == DEPRECATION_STRONG:
        return {"deprecation_strength": DEPRECATION_STRONG}
    is_fresh = push_age == "fresh"
    return {
        "deprecation_strength": deprecation_strength,
        "has_stopped": has_stopped,
        "push_age": push_age,
        "flow_trend": None if is_fresh else flow_trend,
        "release_age": None if is_fresh else release_age,
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
