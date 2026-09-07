#!/usr/bin/env python3
"""Calibration harness for repository stability + the maintenance-state model.

Runs the real scan path (`commits_batch` + `repository_activity_batch` + `readmes_batch` +
registry metadata -> `repository_stability` -> `assess_maintenance`) against a hand-labelled
4-state corpus of live GitHub repositories and reports:

  1. `gap_cv` does not correlate with commit volume across the `maintained` set.
  2. Every `abandoned` repo is flagged `has_stopped`, and `benjaminp/six` specifically is NOT
     flagged (the headline "finished, not dead" case). Deprecated repos are validated by the
     confusion matrix instead - a deprecated package can still carry a live repo.
  3. No repo that committed within the last RECENT_ACTIVITY_DAYS (30) is flagged.

  + a confusion matrix, multiclass Brier score and reliability curve for the naive-Bayes
    maintenance model over the 4 states.

The three gap checks drive the exit code; the model metrics are informational until the
likelihood tables in `risk/maintenance.py` are tuned against this corpus (then promote
"Brier <= 0.20 and diagonal >= 70%" to a hard check here).

Needs a token:

    OSSIQ_GITHUB_TOKEN=ghp_... uv run python qa/calibrate_stability.py

This is a QA script, not a pytest - it hits the network and is kept out of `just qa`.
"""

import logging
import statistics
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ossiq.adapters.api_github import SourceCodeProviderApiGithub
from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.clients import install_requests_cache
from ossiq.domain.package import Package
from ossiq.risk.maintenance import (
    NOT_MAINTAINED,
    STATES,
    MaintenanceAssessment,
    MaintenanceState,
    assess_maintenance,
    deprecation_evidence,
    gated_observations,
    push_age_bucket,
)
from ossiq.risk.stability import engagement_window_since, has_stopped
from ossiq.service.project.stability import RepositoryStability, repository_stability
from ossiq.settings import Settings
from ossiq.timeutil import age_days_from_iso


@dataclass(frozen=True)
class CorpusEntry:
    """One hand-labelled repository. `pypi` / `npm` enable the registry deprecation signals."""

    state: MaintenanceState
    pypi: str | None = None
    npm: str | None = None
    note: str = ""


M = MaintenanceState
# owner/repo -> CorpusEntry. Labels are hand-verified against last-commit HEAD date, archived
# flag, PyPI trove Development Status, all-releases-yanked, npm `deprecated`, release cadence and
# the top of the README. Full label pass done 2026-08-31 (GitHub API + PyPI/npm metadata) -
# see qa/manual/stability-calibrate.md Step 3; the `note=` on each non-obvious entry records the
# evidence found.
CORPUS: dict[str, CorpusEntry] = {
    # --- maintained: commit within ~3 months, flow keeps pace -------------------------------
    "astral-sh/ruff": CorpusEntry(M.MAINTAINED, pypi="ruff"),
    "astral-sh/uv": CorpusEntry(M.MAINTAINED, pypi="uv"),
    "numpy/numpy": CorpusEntry(M.MAINTAINED, pypi="numpy"),
    "pandas-dev/pandas": CorpusEntry(M.MAINTAINED, pypi="pandas"),
    "django/django": CorpusEntry(M.MAINTAINED, pypi="django"),
    "pallets/flask": CorpusEntry(M.MAINTAINED, pypi="flask"),
    "pallets/werkzeug": CorpusEntry(M.MAINTAINED, pypi="werkzeug"),
    "pallets/click": CorpusEntry(M.MAINTAINED, pypi="click"),
    "psf/requests": CorpusEntry(M.MAINTAINED, pypi="requests"),
    "psf/black": CorpusEntry(M.MAINTAINED, pypi="black"),
    "pydantic/pydantic": CorpusEntry(M.MAINTAINED, pypi="pydantic"),
    "fastapi/fastapi": CorpusEntry(M.MAINTAINED, pypi="fastapi"),
    "encode/starlette": CorpusEntry(M.MAINTAINED, pypi="starlette"),
    "pypa/pip": CorpusEntry(M.MAINTAINED, pypi="pip"),
    "pypa/setuptools": CorpusEntry(M.MAINTAINED, pypi="setuptools"),
    "python-attrs/attrs": CorpusEntry(M.MAINTAINED, pypi="attrs"),
    "sqlalchemy/sqlalchemy": CorpusEntry(M.MAINTAINED, pypi="sqlalchemy"),
    "urllib3/urllib3": CorpusEntry(M.MAINTAINED, pypi="urllib3"),
    "pytest-dev/pytest": CorpusEntry(M.MAINTAINED, pypi="pytest"),
    "boto/boto3": CorpusEntry(M.MAINTAINED, pypi="boto3"),
    "pyca/cryptography": CorpusEntry(M.MAINTAINED, pypi="cryptography"),
    "giampaolo/psutil": CorpusEntry(M.MAINTAINED, pypi="psutil"),
    "expressjs/express": CorpusEntry(M.MAINTAINED, npm="express"),
    "axios/axios": CorpusEntry(M.MAINTAINED, npm="axios"),
    "tqdm/tqdm": CorpusEntry(
        M.MAINTAINED, pypi="tqdm", note="live project (was noamraph/tqdm - the author's archived throwaway fork)"
    ),
    "chardet/chardet": CorpusEntry(
        M.MAINTAINED, pypi="chardet", note="active v7 ground-up rewrite; 7.6.0 released 2026-08-14, commit within days"
    ),
    # --- winding_down: mature, deliberately low-churn, no hard deprecation marker -----------
    "benjaminp/six": CorpusEntry(M.WINDING_DOWN, pypi="six", note="headline: finished, not dead"),
    "certifi/python-certifi": CorpusEntry(
        M.WINDING_DOWN, pypi="certifi", note="data-only, steady cadence release (borderline maintained)"
    ),
    "yaml/pyyaml": CorpusEntry(M.WINDING_DOWN, pypi="pyyaml"),
    "stub42/pytz": CorpusEntry(
        M.WINDING_DOWN,
        pypi="pytz",
        note="PyPI self-classifies '6 - Mature'; docs steer to stdlib zoneinfo, tzdata cadence only",
    ),
    "encode/httpx": CorpusEntry(
        M.WINDING_DOWN, pypi="httpx", note="gray zone: ~6mo commit gap, ~20mo since 0.28.1 (2024-12)"
    ),
    "pallets/markupsafe": CorpusEntry(
        M.WINDING_DOWN, pypi="markupsafe", note="tiny finished lib; ~11mo since 3.0.3 (2025-09), active parent org"
    ),
    "hukkin/tomli": CorpusEntry(
        M.WINDING_DOWN, pypi="tomli", note="scope ~complete (stdlib tomllib since 3.11); not archived/deprecated"
    ),
    "dateutil/dateutil": CorpusEntry(M.WINDING_DOWN, pypi="python-dateutil"),
    "un33k/python-slugify": CorpusEntry(M.WINDING_DOWN, pypi="python-slugify"),
    "pypa/distlib": CorpusEntry(
        M.WINDING_DOWN, pypi="distlib", note="low-churn single-maintainer; commit ~3mo, v0.4.3 (borderline maintained)"
    ),
    "PyCQA/mccabe": CorpusEntry(
        M.WINDING_DOWN, pypi="mccabe", note="finished-scope flake8 plugin; last commit ~2mo, no activity decline"
    ),
    "moment/moment": CorpusEntry(
        M.WINDING_DOWN,
        npm="moment",
        note="'maintenance mode' + names successors, but still committed and NOT npm-deprecated",
    ),
    "lodash/lodash": CorpusEntry(
        M.WINDING_DOWN,
        npm="lodash",
        note="README declares 'Feature-Complete maturity stage' (STA-funded, new TSC); 4.18.1 2026-04",
    ),
    "pallets/jinja": CorpusEntry(
        M.WINDING_DOWN,
        pypi="jinja2",
        note="frozen since 2025-06 (housekeeping only); not archived, pallets org still active",
    ),
    "pallets/itsdangerous": CorpusEntry(
        M.WINDING_DOWN,
        pypi="itsdangerous",
        note="tiny finished lib; frozen since 2025-06, 2.2.0 2024-04, active org, not archived",
    ),
    # --- abandoned: a year+ of zero development, not formally deprecated --------------------
    "gabrielfalcao/lettuce": CorpusEntry(M.ABANDONED, pypi="lettuce"),
    "mitsuhiko/flask-oldsessions": CorpusEntry(M.ABANDONED, note="repo resolves; ~14y dead, no marker"),
    "jashkenas/coffeescript": CorpusEntry(
        M.ABANDONED, npm="coffeescript", note="~3y no commit, ~6y no release; superseded by TS/ES6, no formal EOL"
    ),
    "substack/node-browserify": CorpusEntry(
        M.ABANDONED, npm="browserify", note="~2y no commit, ~23mo since v17.0.1; maintainer stepped back, no formal EOL"
    ),
    "celery/django-celery": CorpusEntry(
        M.ABANDONED,
        pypi="django-celery",
        note="maintainer seeking sponsors, not contributing; >15mo since real dev; not archived",
    ),
    "petkaantonov/bluebird": CorpusEntry(
        M.ABANDONED,
        npm="bluebird",
        note="~1.8y no commit, v3.7.2 2019; superseded by native Promises, not archived/deprecated",
    ),
    "tj/co": CorpusEntry(
        M.ABANDONED, npm="co", note="~10y no commit; superseded by async/await, not archived/deprecated"
    ),
    "nvbn/thefuck": CorpusEntry(
        M.ABANDONED, pypi="thefuck", note="~2.6y no commit, 3.32 2022; ~88k stars, not archived"
    ),
    "psf/requests-html": CorpusEntry(
        M.ABANDONED, pypi="requests-html", note="~3.4y no commit, 0.10.0 2019; not archived"
    ),
    "kennethreitz/maya": CorpusEntry(
        M.ABANDONED, pypi="maya", note="~2.1y no commit, 0.6.1 2019; kennethreitz menagerie, not archived"
    ),
    "defunkt/pystache": CorpusEntry(
        M.ABANDONED, pypi="pystache", note="~12y no commit; stale-extreme datapoint, not archived"
    ),
    "nose-devs/nose": CorpusEntry(
        M.ABANDONED,
        pypi="nose",
        note="~10y dead, no successor named in repo/PyPI; EOL notice is readthedocs-only, not machine-readable",
    ),
    # --- deprecated: archived / registry-deprecated / inactive classifier / successor named -
    "noirbizarre/flask-restplus": CorpusEntry(
        M.DEPRECATED, pypi="flask-restplus", note="not archived; ~6.6y dead, README -> flask-restx successor"
    ),
    "mozilla/bleach": CorpusEntry(M.DEPRECATED, pypi="bleach", note="archived; Mozilla EOL announcement 2023-01"),
    "getsentry/raven-python": CorpusEntry(M.DEPRECATED, pypi="raven", note="archived, -> sentry-sdk"),
    "boto/boto": CorpusEntry(M.DEPRECATED, pypi="boto", note="archived, -> boto3"),
    "kennethreitz/clint": CorpusEntry(M.DEPRECATED, pypi="clint", note="GitHub repo archived"),
    "request/request": CorpusEntry(M.DEPRECATED, npm="request", note="npm-deprecated (repo not archived)"),
    "gotwarlost/istanbul": CorpusEntry(M.DEPRECATED, npm="istanbul", note="npm deprecate -> nyc"),
    "kriskowal/q": CorpusEntry(M.DEPRECATED, npm="q", note="archived + npm-deprecated -> native Promises"),
    "stevemao/left-pad": CorpusEntry(
        M.DEPRECATED, npm="left-pad", note="archived + npm-deprecated -> String.prototype.padStart"
    ),
    "dlitz/pycrypto": CorpusEntry(
        M.DEPRECATED, pypi="pycrypto", note="archived; superseded by pycryptodome (had unpatched CVEs)"
    ),
}

RECENT_ACTIVITY_DAYS = 30
"""A repo whose last sampled commit is newer than this is unambiguously live - flagging it is a
false positive regardless of label. Fixed below MIN_SILENCE_DAYS on purpose: check 3 then catches
a regression that weakens the floor, or a bug in the silence-days computation, rather than
re-asserting the conjunction's own threshold."""

GAP_CV_VOLUME_CORRELATION_CEILING = 0.5
"""Max |Pearson r| between gap_cv and commits/day across the maintained set."""


class ResourceLimitCounter(logging.Handler):
    """Tallies the RESOURCE_LIMITS_EXCEEDED warnings `graphql_payload` emits, so GraphQL
    under-sampling shows up in the harness output instead of scrolling past as a log line."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.count = 0

    def emit(self, record: logging.LogRecord) -> None:
        if "resource limit" in record.getMessage().lower():
            self.count += 1


@dataclass
class ActivityCoverage:
    """What the GraphQL activity fetch actually returned - the confounder behind any flow verdict."""

    resource_limit_hits: int
    missing: list[str]


@dataclass
class Row:
    """One repository's measured signals, plus its hand label."""

    repo: str
    entry: CorpusEntry
    stability: RepositoryStability | None
    days_since_push: int | None
    deprecation_strength: str
    maintenance: MaintenanceAssessment | None = field(default=None)

    @property
    def label(self) -> str:
        return self.entry.state.value

    @property
    def measured(self) -> bool:
        return self.stability is not None

    @property
    def commits_per_day(self) -> float | None:
        if self.stability is None or not self.stability.span_days:
            return None
        return self.stability.commits_sampled / self.stability.span_days

    @property
    def silence_days(self) -> float | None:
        return self.stability.silence_days if self.stability else None

    @property
    def stopped(self) -> bool | None:
        if self.stability is None:
            return None
        return has_stopped(self.stability.silence_p, self.stability.silence_days)


def registry_packages(settings: Settings) -> dict[str, Package]:
    """Fetch PyPI + npm metadata for every corpus entry that names a registry package."""
    packages: dict[str, Package] = {}
    pypi_names = [entry.pypi for entry in CORPUS.values() if entry.pypi]
    npm_names = [entry.npm for entry in CORPUS.values() if entry.npm]
    if pypi_names:
        packages.update(PackageRegistryApiPypi(settings).packages_info_batch(pypi_names))
    if npm_names:
        packages.update(PackageRegistryApiNpm(settings).packages_info_batch(npm_names))
    return packages


def calibrate_cache_path(settings: Settings) -> str:
    """A cache file dedicated to the harness - never the one real scans share, so a 7-day TTL on
    everything here cannot serve stale registry data to `ossiq status`."""
    return str(Path(settings.cache_destination).with_name("calibrate-cache.sqlite3"))


def build_rows() -> tuple[list[Row], ActivityCoverage]:
    """Fetch every signal for the whole corpus in parallel and score each repo."""
    settings = Settings()
    if not settings.github_token:
        sys.exit("OSSIQ_GITHUB_TOKEN is required - unauthenticated GitHub cannot sample this corpus.")

    # Everything at the 7-day stability TTL in a harness-only cache: a re-run inside the week is
    # fully offline and deterministic. `rm` the file (path printed below) to force a fresh sample.
    cache_path = calibrate_cache_path(settings)
    print(f"cache: {cache_path}  (rm to force a fresh sample)")
    install_requests_cache(cache_path, settings.stability_cache_ttl, settings.stability_cache_ttl)

    counter = ResourceLimitCounter()
    logging.getLogger("ossiq.clients.client_github").addHandler(counter)

    provider = SourceCodeProviderApiGithub(settings)
    urls = {f"https://github.com/{repo}": repo for repo in CORPUS}
    url_list = list(urls)
    commits_by_url = provider.commits_batch(url_list)
    activity_by_url = provider.repository_activity_batch(url_list, engagement_window_since())
    repos_by_url = provider.repositories_info_batch(url_list)
    readmes_by_url = provider.readmes_batch(url_list)
    packages = registry_packages(settings)

    coverage = ActivityCoverage(
        resource_limit_hits=counter.count,
        missing=sorted(repo for url, repo in urls.items() if url not in activity_by_url),
    )

    rows: list[Row] = []
    for url, repo in urls.items():
        entry = CORPUS[repo]
        stability = repository_stability(commits_by_url.get(url, []), None, activity_by_url.get(url))
        repository = repos_by_url.get(url)
        package = packages.get(entry.pypi or "") or packages.get(entry.npm or "")
        days_since_push = age_days_from_iso(repository.pushed_at) if repository else None

        evidence = deprecation_evidence(
            archived=repository.archived if repository else None,
            classifiers=package.classifiers if package else [],
            all_releases_yanked=package.all_releases_yanked if package else False,
            npm_deprecated=package.is_deprecated if package else False,
            deprecation_message=package.deprecation_message if package else None,
            repo_description=repository.description if repository else None,
            summary=package.description if package else None,
            topics=repository.topics if repository else [],
            readme_head=readmes_by_url.get(url),
            pinned_titles=(activity_by_url.get(url) or {}).get("pinned_titles", []),
        )

        observations = gated_observations(
            deprecation_strength=evidence.strength if evidence.signals else None,
            has_stopped=has_stopped(stability.silence_p, stability.silence_days) if stability is not None else None,
            push_age=push_age_bucket(days_since_push),
            flow_trend=stability.flow_trend if stability else None,
        )
        rows.append(
            Row(
                repo=repo,
                entry=entry,
                stability=stability,
                days_since_push=days_since_push,
                deprecation_strength=evidence.strength,
                maintenance=assess_maintenance(observations),
            )
        )
    return rows, coverage


def num(value: float | None, width: int = 7, places: int = 3) -> str:
    """Right-aligned fixed-width number, or a dash when the value is unmeasured."""
    return f"{value:>{width}.{places}f}" if value is not None else f"{'-':>{width}}"


def print_table(rows: list[Row]) -> None:
    header = (
        f"{'repo':<28} {'label':<13} {'gap_cv':>8} {'commits':>8} {'silence_d':>10} {'stopped':>8} "
        f"{'push_d':>7} {'depr':>7} {'flow':>10} {'predicted':<13} {'risk':>6}"
    )
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda r: (r.label, r.repo)):
        stability = row.stability
        predicted = row.maintenance.state if row.maintenance else "-"
        risk = row.maintenance.p_not_maintained if row.maintenance else None
        gap_cv = stability.gap_cv if stability else None
        commits = stability.commits_sampled if stability else 0
        flow = (stability.flow_trend if stability else None) or "-"
        print(
            f"{row.repo:<28} {row.label:<13} {num(gap_cv, 8):>8} {commits:>8} "
            f"{num(row.silence_days, 10, 1):>10} {str(row.stopped):>8} "
            f"{('-' if row.days_since_push is None else row.days_since_push):>7} {row.deprecation_strength:>7} "
            f"{flow:>10} {predicted:<13} {num(risk, 6, 2)}"
        )


def check_gap_cv_decoupled(maintained: list[Row]) -> list[str]:
    """Check 1: |Pearson r| between gap_cv and commits/day across the maintained set is low."""
    pairs = [
        (r.stability.gap_cv, r.commits_per_day)
        for r in maintained
        if r.stability and r.stability.gap_cv is not None and r.commits_per_day is not None
    ]
    if len(pairs) < 5:
        print("\ncheck 1: skipped - fewer than 5 maintained repos with a gap_cv")
        return []

    gap_cvs = [gap_cv for gap_cv, _ in pairs]
    volumes = [volume for _, volume in pairs]
    correlation = statistics.correlation(gap_cvs, volumes)
    print(
        f"\ncheck 1: gap_cv vs commits/day Pearson r = {correlation:+.2f} across {len(pairs)} maintained repos "
        f"(gap_cv {min(gap_cvs):.2f}-{max(gap_cvs):.2f}, volume {min(volumes):.1f}-{max(volumes):.1f}/day)"
    )
    if abs(correlation) > GAP_CV_VOLUME_CORRELATION_CEILING:
        return [f"check 1: |r| {abs(correlation):.2f} - gap_cv is tracking commit volume"]
    return []


def check_abandonment_caught(rows: list[Row]) -> list[str]:
    """Check 2: every `abandoned` repo is flagged has_stopped; six is not.

    Scoped to `abandoned`, not `deprecated`: a deprecated package can carry a live repo (a
    final "this is deprecated" commit, CI bumps, a slow security patch stream) - its signal
    comes from `deprecation_evidence`, not the commit gap. The confusion matrix is what
    validates the `deprecated` verdict.
    """
    failures = [
        f"check 2: {row.repo} labelled abandoned but has_stopped={row.stopped}"
        for row in rows
        if row.entry.state == MaintenanceState.ABANDONED and row.measured and not row.stopped
    ]
    six = next((r for r in rows if r.repo == "benjaminp/six"), None)
    if six is not None and six.measured and six.stopped:
        failures.append("check 2: benjaminp/six flagged has_stopped - the headline case the design keeps clear")
    return failures


def report_deprecated_still_live(rows: list[Row]) -> None:
    """Informational: deprecated repos that are not has_stopped - fine, `deprecation_evidence`
    carries these, but worth seeing which ones the commit channel alone would miss."""
    live = [row for row in rows if row.entry.state == MaintenanceState.DEPRECATED and row.measured and not row.stopped]
    if live:
        print("\ndeprecated but still committing (not a failure - deprecation evidence carries these):")
        for row in live:
            print(f"  - {row.repo}: silent {row.silence_days:.0f}d, depr={row.deprecation_strength}")


def check_no_live_false_positive(rows: list[Row]) -> list[str]:
    """Check 3: no repo that committed within RECENT_ACTIVITY_DAYS is flagged."""
    return [
        f"check 3: {row.repo} ({row.label}) committed {row.silence_days:.0f}d ago but is flagged has_stopped"
        for row in rows
        if row.measured and row.silence_days is not None and row.silence_days < RECENT_ACTIVITY_DAYS and row.stopped
    ]


def scored_pairs(rows: list[Row]) -> list[tuple[Row, MaintenanceAssessment]]:
    """(row, assessment) for every row the model scored - narrows away the None."""
    return [(row, row.maintenance) for row in rows if row.maintenance is not None]


def print_confusion_matrix(rows: list[Row]) -> None:
    """Predicted (argmax posterior) vs hand label, with per-class precision / recall."""
    pairs = scored_pairs(rows)
    matrix: Counter[tuple[str, str]] = Counter((row.label, assessment.state) for row, assessment in pairs)

    print(f"\nconfusion matrix ({len(pairs)} scored repos) - rows = label, cols = predicted:")
    print(f"{'':<14}" + "".join(f"{state[:11]:>13}" for state in STATES) + f"{'recall':>9}")
    diagonal = 0
    for label in STATES:
        row_total = sum(matrix[(label, predicted)] for predicted in STATES)
        cells = "".join(f"{matrix[(label, predicted)]:>13}" for predicted in STATES)
        recall = matrix[(label, label)] / row_total if row_total else 0.0
        diagonal += matrix[(label, label)]
        print(f"{label:<14}{cells}{recall:>9.2f}")
    precision_line = f"{'precision':<14}"
    for predicted in STATES:
        col_total = sum(matrix[(label, predicted)] for label in STATES)
        precision = matrix[(predicted, predicted)] / col_total if col_total else 0.0
        precision_line += f"{precision:>13.2f}"
    print(precision_line)
    print(f"  diagonal accuracy: {diagonal / len(pairs):.2%}" if pairs else "  no scored repos")


def multiclass_brier(rows: list[Row]) -> None:
    """Mean over scored repos of sum_s (p_s - 1[label = s])^2, overall and per class."""
    pairs = scored_pairs(rows)
    if not pairs:
        print("\nBrier score: no scored repos")
        return
    per_class: dict[str, list[float]] = {state: [] for state in STATES}
    total = 0.0
    for row, assessment in pairs:
        score = sum((assessment.posterior[state] - (1.0 if row.label == state else 0.0)) ** 2 for state in STATES)
        total += score
        per_class[row.label].append(score)
    print(f"\nmulticlass Brier score: {total / len(pairs):.3f}  (0 = perfect, lower is better)")
    for state in STATES:
        values = per_class[state]
        if values:
            print(f"  {state:<14} {statistics.mean(values):.3f}  (n={len(values)})")


def reliability_curve(rows: list[Row]) -> None:
    """Predicted P(not maintained) in deciles vs the observed not-maintained rate."""
    pairs = scored_pairs(rows)
    if not pairs:
        return
    print("\nreliability curve - predicted P(not maintained) vs observed:")
    print(f"  {'bucket':<12}{'n':>4}{'mean pred':>12}{'observed':>11}")
    for lower in range(10):
        low, high = lower / 10, (lower + 1) / 10
        bucket = [
            (row, assessment)
            for row, assessment in pairs
            if low <= assessment.p_not_maintained < high or (high == 1.0 and assessment.p_not_maintained == 1.0)
        ]
        if not bucket:
            continue
        mean_pred = statistics.mean(assessment.p_not_maintained for _, assessment in bucket)
        observed = sum(1 for row, _ in bucket if row.entry.state in NOT_MAINTAINED) / len(bucket)
        flag = "  <-- off diagonal" if abs(mean_pred - observed) > 0.2 else ""
        print(f"  {low:.1f}-{high:.1f}{'':<4}{len(bucket):>4}{mean_pred:>12.2f}{observed:>11.2f}{flag}")


def report_activity_coverage(coverage: ActivityCoverage) -> None:
    """GraphQL under-sampling, made visible."""
    print(f"\nGraphQL activity: {coverage.resource_limit_hits} resource-limit hit(s)")
    if coverage.missing:
        print(f"  no activity payload for {len(coverage.missing)}: {', '.join(coverage.missing)}")


def main() -> int:
    rows, coverage = build_rows()
    print_table(rows)

    measured = [r for r in rows if r.measured]
    maintained = [r for r in measured if r.entry.state == MaintenanceState.MAINTAINED]

    abandonment_failures = check_abandonment_caught(rows)
    failures = check_gap_cv_decoupled(maintained) + abandonment_failures + check_no_live_false_positive(rows)

    report_activity_coverage(coverage)
    report_deprecated_still_live(rows)
    print_confusion_matrix(rows)
    multiclass_brier(rows)
    reliability_curve(rows)

    print(f"\n{len(rows)} repos, {len(measured)} measured, {len(abandonment_failures)} label/has_stopped mismatches")

    if failures:
        print("\nFAILED:")
        for message in failures:
            print(f"  - {message}")
        return 1
    print("\nAll three gap checks passed. Model metrics above are informational until the tables are tuned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
