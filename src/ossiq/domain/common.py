"""
Put all the important constants in one place to avoid
mutual dependencies.
"""

import importlib.metadata
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum, StrEnum
from typing import Generic, TypeVar
from urllib.parse import quote

T = TypeVar("T")

# Source of versions data within target source code repository
VERSION_DATA_SOURCE_GITHUB_RELEASES = "GITHUB-RELEASES"
VERSION_DATA_SOURCE_GITHUB_TAGS = "GITHUB-TAGS"


class RepositoryProvider(StrEnum):
    PROVIDER_GITHUB = "GITHUB"
    PROVIDER_UNKNOWN = "UNKNOWN"


class ProjectPackagesRegistry(StrEnum):
    NPM = "NPM"
    PYPI = "PYPI"


class CveDatabase(StrEnum):
    OSV = "OSV"
    GHSA = "GHSA"
    NVD = "NVD"
    SNYK = "SNYK"
    OTHER = "OTHER"


class UserInterfaceType(Enum):
    """
    What kind of presentation methods available. Default likely should be Console,
    potentailly could be HTML and JSON/YAML.
    """

    CONSOLE = "console"
    HTML = "html"
    JSON = "json"
    AGENT = "agent"


class Command(Enum):
    """
    List of available commands, used by presentation layer to map
    command with respective presentation layer.
    """

    STATUS = "status"
    EXPORT = "export"
    HTML = "html"
    INFO = "info"
    ADD = "add"
    PLAN = "plan"
    APPLY = "apply"
    UPDATE_CONTEXT = "update-context"


class ExportUnknownSchemaVersion(StrEnum):
    """Supported export schema versions."""

    UNKNOWN = "UNKNOWN"


class ExportJsonSchemaVersion(StrEnum):
    """Supported export schema versions."""

    V1_5 = "1.5"


class ConstraintType(StrEnum):
    """How a version constraint was applied for a dependency.

    Priority ordering (highest wins for display): OVERRIDE > ADDITIVE > PINNED > NARROWED > DECLARED
    """

    DECLARED = "DECLARED"  # loose/default — any, ^x, ~x, >=x (lower-bound only)
    NARROWED = "NARROWED"  # explicit range with bounds — >=x <y, ~=x, ==x.*, compound
    PINNED = "PINNED"  # exactly one version — ==x.y.z (PyPI) or bare x.y.z (npm)
    ADDITIVE = "ADDITIVE"  # narrows range without adding a direct dep (pip -c, uv constraint-dependencies)
    OVERRIDE = "OVERRIDE"  # completely replaces resolution (npm overrides, uv override-dependencies)


class RecommendationRung(StrEnum):
    """Which rung of the version ladder a ScanRecord.recommended_version came from.

    SOLVER and IN_RANGE sit inside the declared version_constraint and are safe for the writers
    to apply directly. IN_MAJOR and LATEST are only reachable by widening the constraint first —
    build_update_plan holds those back into UpdatePlan.held_for_widening instead of writing them.
    """

    SOLVER = "solver"  # the SAT solver's own pick (post apply_recommendations/clamp_recommendations)
    IN_RANGE = "in_range"  # ladder fallback: newest version satisfying the declared constraint
    IN_MAJOR = "in_major"  # ladder fallback: newest version within the installed major line
    LATEST = "latest"  # ladder fallback: newest version overall


WIDENING_RUNGS: frozenset[RecommendationRung] = frozenset({RecommendationRung.IN_MAJOR, RecommendationRung.LATEST})
"""Rungs only reachable by widening the declared constraint first. The single definition — it
decides whether `ossiq apply` may write, whether an entry lands in UpdatePlan.held_for_widening,
whether an agent entry carries requires_constraint_widening, and whether "Constrained" is the
right next action. Anything not in here is writable as-is."""

RUNG_ORDER: Mapping[RecommendationRung, int] = {
    RecommendationRung.IN_RANGE: 0,
    RecommendationRung.IN_MAJOR: 1,
    RecommendationRung.LATEST: 2,
}
"""Total order over the three ladder rungs a strategy can reach. SOLVER sits outside the ladder
and is never compared here, so indexing this with it is a KeyError by design."""


def rung_scope_label(rung: RecommendationRung | None) -> str:
    """How far a widening rung reaches, in the wording the plan table and info block both use.

    Args:
        rung: The rung a recommendation came from.

    Returns:
        "new major" for LATEST, "same major" for anything else.
    """
    return "new major" if rung == RecommendationRung.LATEST else "same major"


def display_package_name(package_name: str, dependency_name: str | None) -> str:
    """How to name a dependency to a human: the manifest key, plus the registry name when aliased.

    npm aliases let one package be installed several times under different keys
    (`uuid-v7: "npm:uuid@^7.0.0"`), and every one of them carries `uuid` as its registry name.
    Printing only that name renders them as indistinguishable duplicate rows.

    One function rather than a property on each of ScanRecord and UpdateEntry, so the scan and the
    update plan can never name the same dependency two different ways.

    Args:
        package_name: The canonical registry name.
        dependency_name: The manifest key, when known and possibly different.

    Returns:
        "key (registry-name)" for an alias, the plain name otherwise.
    """
    if dependency_name and dependency_name != package_name:
        return f"{dependency_name} ({package_name})"
    return package_name


@dataclass(frozen=True)
class RejectedCandidate:
    """A release that would otherwise have been a candidate, held back by a transitive conflict."""

    version: str
    reason: str


@dataclass(frozen=True)
class CooldownHold:
    """The newest reachable release, withheld because it is younger than the cooldown period.

    Carries the version rather than a rendered sentence so every surface can word it its own way;
    `age_days` is None when the registry gave no publish date, which is also the only case where a
    release is treated as aged rather than fresh (never hold on missing data).
    """

    version: str
    age_days: int | None
    cooldown_period: int


class ModuleSystem(StrEnum):
    """A package release's own module format, as declared by its registry metadata (npm only).

    Derived heuristically from `type`/`exports` in the npm registry doc — not a spec-complete
    `exports`-map resolver. Always None on PyPI releases (no analogous machine-readable signal).
    """

    ESM_ONLY = "esm-only"
    CJS = "cjs"
    DUAL = "dual"


class EngineContextSource(StrEnum):
    """Which source supplied the engine versions a record's compatibility was checked against.

    Each engine is held to the stricter of the probed runtime and the project's own manifest floor,
    so DECLARED means that floor (Project.engine_constraints) is what binds for at least one
    engine, DETECTED that the probe (see adapters.runtime_environment) binds throughout, and NONE
    that neither was available.
    """

    DETECTED = "detected"
    DECLARED = "declared"
    NONE = "none"


# Which engine key a registry's packages declare requirements against. Also decides which runtime
# probes are worth spawning: a pure-PyPI scan has no use for `node --version`.
ENGINE_CONTEXT_KEY_BY_REGISTRY: Mapping[ProjectPackagesRegistry, str] = {
    ProjectPackagesRegistry.NPM: "node",
    ProjectPackagesRegistry.PYPI: "python",
}


@dataclass(frozen=True)
class EngineContext:
    """The runtime versions a scan checked engine requirements against, and where they came from.

    One value rather than two parallel fields: the versions and their provenance were threaded
    separately through the pipeline and the renderers, and the pair drifted - one scan reported
    `detected` on actionable records and `none` on the rest. `versions` is a plain dict (mutable
    inside a frozen dataclass, as elsewhere in the codebase); treat it as read-only.
    """

    versions: dict[str, str] = field(default_factory=dict)
    source: EngineContextSource = EngineContextSource.NONE


class ScanStep(StrEnum):
    """The stages a project scan moves through, and the keys its completeness is reported under.

    One definition shared by the pipeline that emits the events (`service.project.scan`), the
    stepper that draws them (`ui.system.SCAN_STEPS` supplies only the labels), and
    `DataCompleteness.by_step`. They used to be magic strings duplicated across all three.

    Only REPOSITORIES, VULNERABILITIES and EPSS report a DataSourceStatus:

    - PACKAGES / VERSIONS read the registry port the solver also depends on
      (`packages_info_batch`, `package_versions`). That is a per-package cached read, not one
      batch run, so widening its return type to carry a status would ripple through `solver/`,
      `clamp_recommendations` and `library_scan`. Deferred deliberately.
    - PROJECT / SOLVER touch no external data source at all, so a DataSourceStatus would be a
      category error, not a missing feature.
    """

    PROJECT = "project"
    PACKAGES = "packages"
    REPOSITORIES = "repositories"
    VULNERABILITIES = "vulnerabilities"
    EPSS = "epss"
    VERSIONS = "versions"
    SOLVER = "solver"


class DataSourceStatus(StrEnum):
    """Whether an external data source (OSV, GitHub, ...) actually delivered data for this scan.

    B4: a scan step reaching completion is not the same as it succeeding. These are the explicit
    per-source states the defect report calls for, replacing a checkmark that previously meant
    only "we moved past this step" regardless of whether any data came back.
    """

    OK = "ok"
    PARTIAL = "partial"  # some chunks failed or were dropped; the rest of the data is real
    UNREACHABLE = "unreachable"  # nothing came back at all - connection/timeout/HTTP failures
    RATE_LIMITED = "rate_limited"  # the source's quota was exhausted mid-scan


class DegradeReason(StrEnum):
    """Why one fetch inside a data source failed - the question `DataSourceStatus` can't answer.

    Three renamed repositories and an exhausted quota both render as a bare `partial`, which is
    exactly how a dead repo URL gets mistaken for a rate limit. The status says whether the source
    delivered; this says what stopped it, so the warning can name the cause.
    """

    NOT_FOUND = "not_found"  # 404 - the resource is gone, renamed, or private
    RATE_LIMITED = "rate_limited"  # the source's quota ran out mid-fetch
    UNAVAILABLE = "unavailable"  # timeouts, connection errors, 5xx - retried and still failing
    REJECTED = "rejected"  # other 4xx: bad credentials, validation, blocked resource
    EMPTY_RESPONSE = "empty_response"  # 2xx with no JSON body to map
    ABORTED = "aborted"  # dropped with no attempt at all, after a global abort
    UNKNOWN = "unknown"  # the response arrived but mapping it raised


@dataclass(frozen=True)
class RateLimitBudget:
    """What one API's quota looked like, either observed mid-scan or forecast before it.

    `needed` is set only by a pre-flight forecast, where the question is "will this scan fit in
    what's left?"; a budget read off a response's headers reports what remained and leaves it None.
    """

    resource: str
    """The quota this covers, as the API names it - GitHub meters `core` and `graphql` apart."""

    limit: int | None = None
    remaining: int | None = None
    reset_at: float | None = None
    """Epoch seconds at which the window rolls over, as the API reported it."""

    needed: int | None = None
    """Requests this scan is expected to spend against `resource`, when this is a forecast."""

    @property
    def short_by(self) -> int:
        """How many requests the forecast is short by; 0 when it fits or isn't a forecast."""
        if self.needed is None or self.remaining is None:
            return 0
        return max(0, self.needed - self.remaining)

    @property
    def exhausted(self) -> bool:
        return self.remaining == 0

    def seconds_until_reset(self, now: float) -> float | None:
        """Seconds until the window rolls over, or None when the API didn't say."""
        return max(0.0, self.reset_at - now) if self.reset_at is not None else None

    def worse_of(self, other: "RateLimitBudget") -> "RateLimitBudget":
        """The tighter of two readings of the same resource - the lower `remaining` wins.

        Quota only falls within a window, so the lowest reading is the most recent one; `needed`
        survives from whichever side forecast it.
        """
        if self.remaining is None:
            tighter, looser = other, self  # a reading that says nothing never wins over one that does
        elif other.remaining is None or self.remaining <= other.remaining:
            tighter, looser = self, other
        else:
            tighter, looser = other, self
        return replace(tighter, needed=tighter.needed if tighter.needed is not None else looser.needed)


@dataclass(frozen=True)
class FetchDiagnostics:
    """Why a fetch came back degraded, and what the source's quota looked like while it ran.

    Rule 3 of the architecture: a failed fetch is a value the renderer decides how to show. This
    is that value for the "why" - counts rather than messages, so the wording stays in `ui/`.
    """

    failures: tuple[tuple[DegradeReason, int], ...] = ()
    """(reason, count) pairs, counted over chunks - the same granularity as the status itself."""

    budgets: tuple[RateLimitBudget, ...] = ()
    """One entry per metered resource the fetch touched."""

    def merge(self, other: "FetchDiagnostics") -> "FetchDiagnostics":
        """Combine two fetches' diagnostics: failure counts add, budgets keep the tighter reading."""
        counts: dict[DegradeReason, int] = {}
        for reason, count in self.failures + other.failures:
            counts[reason] = counts.get(reason, 0) + count
        budgets: dict[str, RateLimitBudget] = {}
        for budget in self.budgets + other.budgets:
            known = budgets.get(budget.resource)
            budgets[budget.resource] = known.worse_of(budget) if known else budget
        return FetchDiagnostics(
            failures=tuple(sorted(counts.items())),
            budgets=tuple(budgets[resource] for resource in sorted(budgets)),
        )


def merge_diagnostics(items: Iterable[FetchDiagnostics]) -> FetchDiagnostics:
    """Fold several fetches' diagnostics into the one a scan step reports."""
    merged = FetchDiagnostics()
    for item in items:
        merged = merged.merge(item)
    return merged


@dataclass(frozen=True)
class SourceFetch(Generic[T]):
    """What one fetch from an external source returned, and whether the source delivered it.

    Adapters used to answer the second half by leaving a summary on themselves for the caller to
    read afterwards (`last_summary`), which forced the scan pipeline to hold adapter instances
    just to interrogate them. Returning the pair keeps the diagnostic a value, per the house rule
    that lower layers return diagnostics rather than stashing them.
    """

    data: T
    status: DataSourceStatus = DataSourceStatus.OK
    diagnostics: FetchDiagnostics = field(default_factory=FetchDiagnostics)
    """Why the status is what it is - empty when the fetch had nothing to report."""


def combine_statuses(statuses: Iterable[DataSourceStatus]) -> DataSourceStatus:
    """Merge several fetches' outcomes into one status for the source they came from.

    A mix of success and failure is PARTIAL rather than the worse of the two: one failed GitHub
    stream out of four does not mean GitHub was unreachable. RATE_LIMITED wins outright, because
    the cause is a quota that applies to every later call as well.

    Distinct from DataCompleteness.overall, which asks the project-level question ("is this whole
    report degraded?") and is deliberately a plain worst-of.

    Args:
        statuses: The outcomes of the individual fetches that make up one source.

    Returns:
        The single status to report for that source. An empty input is OK - nothing was attempted.
    """
    seen = list(statuses)
    if not seen:
        return DataSourceStatus.OK
    if DataSourceStatus.RATE_LIMITED in seen:
        return DataSourceStatus.RATE_LIMITED
    failed = [s for s in seen if s != DataSourceStatus.OK]
    if not failed:
        return DataSourceStatus.OK
    if len(failed) == len(seen) and all(s == DataSourceStatus.UNREACHABLE for s in failed):
        return DataSourceStatus.UNREACHABLE
    return DataSourceStatus.PARTIAL


@dataclass(frozen=True)
class DataCompleteness:
    """Per-scan-step completeness (B4), keyed by `ScanStep` so the checkmark rendering, the export
    metadata, and the exit-code logic all agree on what actually happened during a scan.

    A step absent from `by_step` is treated as ok - see ScanStep for which steps report a status
    and why the rest cannot.
    """

    by_step: dict[ScanStep, DataSourceStatus] = field(default_factory=dict)

    diagnostics: dict[ScanStep, FetchDiagnostics] = field(default_factory=dict)
    """Why each degraded step degraded, and the quota its source reported while it ran. Optional:
    a step that reports a status but no diagnostics is the old behaviour, not an error."""

    def status_for(self, step: ScanStep) -> DataSourceStatus:
        return self.by_step.get(step, DataSourceStatus.OK)

    def diagnostics_for(self, step: ScanStep) -> FetchDiagnostics:
        return self.diagnostics.get(step, FetchDiagnostics())

    @property
    def budgets(self) -> tuple[RateLimitBudget, ...]:
        """Every metered resource this scan touched, tightest reading per resource."""
        return merge_diagnostics(self.diagnostics.values()).budgets

    @property
    def overall(self) -> DataSourceStatus:
        """Worst status across every tracked step, in the order a user should care about it.

        Deliberately not `combine_statuses`: this answers "is the whole report degraded?", where
        one failed source taints the result. `combine_statuses` answers "did this one source
        deliver?", where a mix of success and failure is PARTIAL rather than the worse of the two.
        """
        statuses = set(self.by_step.values())
        for candidate in (DataSourceStatus.RATE_LIMITED, DataSourceStatus.UNREACHABLE, DataSourceStatus.PARTIAL):
            if candidate in statuses:
                return candidate
        return DataSourceStatus.OK

    @property
    def degraded_steps(self) -> dict[ScanStep, DataSourceStatus]:
        """Only the steps that didn't come back ok - what a warning message should list."""
        return {step: status for step, status in self.by_step.items() if status != DataSourceStatus.OK}


# Domain-specific Exceptions


class UnsupportedProjectType(Exception):
    pass


class UnsupportedPackageRegistry(Exception):
    pass


class UnsupportedRepositoryProvider(Exception):
    pass


class UnknownCommandException(Exception):
    pass


class UnknownUserInterfaceType(Exception):
    pass


class NoPackageVersionsFound(Exception):
    pass


class PackageNotInstalled(Exception):
    pass


_PURL_TYPE: dict[str, str] = {
    "NPM": "npm",
    "PYPI": "pypi",
}


# Leading distribution name in a dependency specifier (stops at version operators, the extras
# bracket, environment markers, whitespace).
_DIST_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")


def normalize_dist_name(spec: str) -> str:
    """Extract and normalise a distribution name from a dependency specifier.

    Strips version operators, extras, environment markers and whitespace, then applies PyPA name
    normalization (lowercase; collapse runs of [-_.] to a single '-'). Scoped npm names survive
    intact apart from case, since the pattern doesn't match a leading '@'.

    Examples:
        "urllib3<2.0"             -> "urllib3"
        "requests[security]>=2.0" -> "requests"
        "My_Package"              -> "my-package"
        "@Scope/Pkg"              -> "@scope/pkg"
    """
    spec = spec.strip()
    m = _DIST_NAME_RE.match(spec)
    name = m.group(1) if m else spec
    return re.sub(r"[-_.]+", "-", name).lower()


class NameValueSpecError(ValueError):
    """A malformed or conflicting `name=value` CLI spec.

    Carries the offending spec and package so a front door can render its own wording without
    parsing the message back out of the string.
    """

    def __init__(self, message: str, *, value: str | None = None, package: str | None = None):
        super().__init__(message)
        self.value = value
        self.package = package


def parse_name_value_specs(
    raw: Iterable[str] | None,
    *,
    separator: str,
    flag: str,
    value_parser: Callable[[str], T],
) -> tuple[tuple[str, T], ...]:
    """Parse repeatable `name<separator>value` CLI specs into normalised (name, value) pairs.

    One parser for `--override pkg==version` and `--strategy-override pkg=tier`, which had
    diverged: only the latter normalised names, so the same spelling resolved to different
    packages depending on which flag you used.

    Args:
        raw: The raw option values, or None when the option was never given.
        separator: What splits the name from the value ("==" or "=").
        flag: The option name, used in error messages.
        value_parser: Turns the value half into its final type; may raise ValueError.

    Returns:
        (canonical_name, parsed_value) pairs, deduplicated, in first-seen order.

    Raises:
        NameValueSpecError: On a malformed spec, or the same package given two conflicting values.
        ValueError: Whatever `value_parser` raises for a value it rejects.
    """
    parsed: dict[str, T] = {}
    for entry in raw or []:
        name, found, value_raw = entry.partition(separator)
        name = name.strip()
        value_raw = value_raw.strip()
        if not found or not name or not value_raw:
            raise NameValueSpecError(f"Invalid {flag} value '{entry}'; expected package{separator}value", value=entry)
        canonical = normalize_dist_name(name)
        value = value_parser(value_raw)
        if canonical in parsed and parsed[canonical] != value:
            raise NameValueSpecError(f"Conflicting {flag} values for '{canonical}'", package=canonical)
        parsed[canonical] = value
    return tuple(parsed.items())


def build_purl(registry: "ProjectPackagesRegistry", name: str, version: str) -> str:
    """
    Build a Package URL (PURL) string per the PURL specification (ECMA-386).

    Examples:
        build_purl(ProjectPackagesRegistry.PYPI, "requests", "2.25.1")
        -> "pkg:pypi/requests@2.25.1"

        build_purl(ProjectPackagesRegistry.NPM, "@babel/core", "7.0.0")
        -> "pkg:npm/%40babel%2Fcore@7.0.0"

    Args:
        registry: The package registry enum value.
        name: The canonical package name (may include npm scope like "@scope/pkg").
        version: The resolved package version string.

    Returns:
        A PURL string in the form "pkg:{type}/{encoded_name}@{version}".
    """
    purl_type = _PURL_TYPE[registry.value]
    # Per PURL spec the name component must be percent-encoded.
    # quote() with safe="" encodes "@" and "/" which appear in npm scoped packages.
    encoded_name = quote(name, safe="")
    return f"pkg:{purl_type}/{encoded_name}@{version}"


def parse_spdx_expression(expr: str | None) -> list[str] | None:
    """
    Parse an SPDX license expression into individual license identifiers.

    Splits on AND/OR boolean operators. Preserves WITH clauses (license exceptions)
    as a single token. Filters out NOASSERTION tokens.

    Examples:
        parse_spdx_expression("Apache-2.0")
        -> ["Apache-2.0"]

        parse_spdx_expression("Apache-2.0 AND BSD-2-Clause")
        -> ["Apache-2.0", "BSD-2-Clause"]

        parse_spdx_expression("MIT OR Apache-2.0")
        -> ["MIT", "Apache-2.0"]

        parse_spdx_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        -> ["GPL-2.0-only WITH Classpath-exception-2.0"]

        parse_spdx_expression("Apache-2.0 AND NOASSERTION")
        -> ["Apache-2.0"]
    """
    if not expr:
        return None

    tokens = re.split(r"\s+(?:AND|OR)\s+", expr)
    licenses = [token.strip().strip("()") for token in tokens]
    licenses = [lic for lic in licenses if lic and lic != "NOASSERTION"]

    return licenses if licenses else None


def get_version():
    """
    Get OSS IQ version
    """
    try:
        return importlib.metadata.version("ossiq")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"
