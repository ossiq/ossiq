"""Version constraint matching for npm/semver and PyPI/PEP 440 dependencies.

Two ecosystems, two constraint languages:

  npm / Node.js semver
    Raw constraint comes from package.json "dependencies" or transitive "requires".
    Syntax reference: https://github.com/npm/node-semver#versions
    Examples: "^1.2.3", "~14.0", ">=8.0.0 <9", "14 || 16"

  PyPI / PEP 440
    Raw constraint comes from requirements.txt, pyproject.toml, or a wheel's
    Requires-Dist metadata field.
    Syntax reference: https://packaging.python.org/en/latest/specifications/dependency-specifiers/
    Examples: ">=1.19.0", ">=8.1.8,<8.4.0", "~=1.4.2", "==3.11.*"

Pipeline:
    raw constraint string
        │
        ├── npm  ->  npm_version_satisfies_range(version, range_constraint)
        │               └─ solver.npm_range (node-semver's range algorithm, ported)
        │
        ├── pypi ->  pypi_version_satisfies_specifier(version, specifier)
        │               └─ univers.PypiVersionRange / PypiVersion
        │
        └── unified -> version_satisfies_constraint(version, constraint | None, registry)
                          dispatches to npm or pypi based on ProjectPackagesRegistry
                          |
                    used by ConstraintEncoder for L1 / implication clauses
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import TypeVar

import semver
from packaging.version import InvalidVersion
from packaging.version import Version as PackagingVersion
from univers.version_constraint import InvalidConstraintsError
from univers.version_range import InvalidVersionRange, PypiVersionRange
from univers.versions import PypiVersion

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.cve import CVE, AffectedRange
from ossiq.domain.version import pad_npm_version
from ossiq.solver.npm_range import parse_loose_semver, parse_npm_range
from ossiq.solver.problem import CandidateVersion

logger = logging.getLogger(__name__)


# ── npm / Node.js semver
# Spec: https://github.com/npm/node-semver#versions


def strip_npm_alias(constraint: str) -> str:
    """Return the embedded range of an npm alias specifier, or the constraint unchanged.

    ``npm:wrap-ansi@^7.0.0`` -> ``^7.0.0``;  ``npm:@scope/pkg@~1.2`` -> ``~1.2``.
    The range is the part after the final ``@``; a non-alias string passes through.
    """
    s = constraint.strip()
    if not s.startswith("npm:"):
        return constraint
    at_idx = s.rfind("@")
    if at_idx > len("npm:"):
        return s[at_idx + 1 :]
    return constraint


def expand_compatible_release(part: str) -> str:
    """Expand ~=X.Y.Z -> >=X.Y.Z,<X.(Y+1).0 for univers compatibility."""
    ver = part[2:].strip()
    parts = ver.split(".")
    upper = parts[:-1]
    upper[-1] = str(int(upper[-1]) + 1)
    return f">={ver},<{'.'.join(upper)}.0"


def preprocess_pypi_specifier(specifier: str) -> str:
    """Expand any ~= clauses in a comma-separated PEP 440 specifier string."""
    return ",".join(
        expand_compatible_release(p.strip()) if p.strip().startswith("~=") else p.strip() for p in specifier.split(",")
    )


def npm_version_satisfies_range(version: str, range_constraint: str, include_prerelease: bool = False) -> bool:
    """Return True if *version* satisfies an npm semver *range_constraint*, as npm would decide.

    Matching is `solver.npm_range`, a port of node-semver's own range algorithm, so every form
    npm accepts means here what it means to npm. An npm alias ("npm:pkg@^1.2.3") is matched
    against its embedded range.

    Args:
        version: The version to test.
        range_constraint: The range as written in a manifest or lockfile.
        include_prerelease: node-semver's ``includePrerelease``. Without it a prerelease
            satisfies only a range that names a prerelease of the same major.minor.patch.

    Returns:
        Whether *version* satisfies the range; True when either side cannot be parsed, so a
        specifier npm resolves outside semver ("latest", a git URL) never hard-blocks.
    """
    try:
        npm_range = parse_npm_range(strip_npm_alias(range_constraint), include_prerelease)
        candidate = parse_loose_semver(version)
    except ValueError as exc:
        logger.debug(
            "npm_version_satisfies_range: version=%r constraint=%r unparseable: %s", version, range_constraint, exc
        )
        return True
    return npm_range.satisfied_by(candidate)


# ── PyPI / PEP 440
# Spec: https://packaging.python.org/en/latest/specifications/dependency-specifiers/


def pypi_version_satisfies_specifier(version: str, specifier: str) -> bool:
    """Return True if *version* satisfies a PEP 440 dependency *specifier*.

    Raises ``InvalidVersionRange`` for non-PEP-440 strings — callers should
    catch it and fall back to npm semver matching.
    """
    return PypiVersion(version) in PypiVersionRange.from_native(preprocess_pypi_specifier(specifier))  # type: ignore


# ── Unified (ecosystem-agnostic)


def version_satisfies_constraint(version: str, constraint: str | None, registry: ProjectPackagesRegistry) -> bool:
    """Return True if *version* satisfies *constraint* for the given *registry*.

    Dispatches directly to the correct parser - no fallback, no exception-based routing.
    An unparseable constraint passes through as True so unknown formats never hard-block.
    """
    if constraint is None:
        return True
    try:
        if registry == ProjectPackagesRegistry.PYPI:
            return pypi_version_satisfies_specifier(version, constraint)
        return npm_version_satisfies_range(version, constraint)
    except (ValueError, InvalidVersionRange, InvalidConstraintsError) as exc:
        logger.debug(
            "version_satisfies_constraint: parse failed version=%r constraint=%r registry=%s error=%s",
            version,
            constraint,
            registry,
            exc,
        )
        return True


def major_key(version: str, registry: ProjectPackagesRegistry) -> tuple[int, int] | None:
    """Return the (epoch, major) identity of *version*'s major line, or None if unparseable.

    PEP 440 epochs are part of the identity: "1!1.0" is deliberately a different major line
    than "1.0", which comparing release tuples alone cannot see. npm has no epoch, so it is
    always 0. A None result never matches another major_key value, so unparseable versions are
    excluded from major-line grouping rather than silently lumped together.
    """
    try:
        if registry == ProjectPackagesRegistry.PYPI:
            parsed = PackagingVersion(version)
            return (parsed.epoch, parsed.release[0] if parsed.release else 0)
        return (0, semver.Version.parse(pad_npm_version(version)).major)
    except (InvalidVersion, ValueError):
        return None


def satisfies_all_constraints(version: str, constraints: list[str], registry: ProjectPackagesRegistry) -> bool:
    """Return True when version satisfies every non-empty constraint in the list."""
    return all(version_satisfies_constraint(version, c, registry) for c in constraints if c)


# ── Advisory exposure

# One ordering per registry; constrained so an interval's bounds and the candidate always compare
# within the same type.
VersionT = TypeVar("VersionT", semver.Version, PackagingVersion)


@functools.cache
def parse_npm_version(version: str) -> semver.Version:
    """Parse an npm release with semver ordering; a partial version ("1.0") is zero-filled.

    Unlike `pad_npm_version`, this keeps a dotted prerelease whole, so "1.0.0-rc.9" and
    "1.0.0-rc.10" stay two different bounds. Raises ValueError when the string isn't semver.
    """
    return semver.Version.parse(version, optional_minor_and_patch=True)


@functools.cache
def parse_pypi_version(version: str) -> PackagingVersion:
    """Parse a PyPI release with PEP 440 ordering; raises ValueError when it isn't PEP 440."""
    return PackagingVersion(version)


def interval_contains(affected_range: AffectedRange, version: str, parse: Callable[[str], VersionT]) -> bool:
    """Whether *version* sits inside one advisory interval; raises ValueError on anything unparseable."""
    candidate = parse(version)
    if affected_range.introduced is not None and candidate < parse(affected_range.introduced):
        return False
    if affected_range.fixed is not None:
        return candidate < parse(affected_range.fixed)
    if affected_range.last_affected is not None:
        return candidate <= parse(affected_range.last_affected)
    return True


def range_contains(affected_range: AffectedRange, version: str, registry: ProjectPackagesRegistry) -> bool:
    """`interval_contains` with the version ordering *registry* uses."""
    if registry == ProjectPackagesRegistry.PYPI:
        return interval_contains(affected_range, version, parse_pypi_version)
    return interval_contains(affected_range, version, parse_npm_version)


def cve_affects_version(cve: CVE, version: str) -> bool:
    """Whether *version* is exposed to *cve*: enumerated by OSV, or inside one of its ranges.

    The only judge of "is this release affected" - npm advisories enumerate nothing, so testing
    `version in cve.affected_versions` read every npm release as clean. Unlike
    `version_satisfies_constraint`, this fails closed: an unparseable version or bound counts as
    affected, because every caller uses a False to call a release safe - the solver stops
    forbidding it, the ladder stops stepping over it, and the agent payload calls it a fix.

    Args:
        cve: The advisory; its `package_registry` picks the version ordering.
        version: The release to judge.

    Returns:
        True when the release is listed or inside a range, or when a range can't be evaluated.
    """
    if version in cve.affected_versions:
        return True
    for affected_range in cve.affected_ranges:
        try:
            if range_contains(affected_range, version, cve.package_registry):
                return True
        except ValueError as exc:
            logger.debug("cve_affects_version: %s %r vs %r unparseable (%s)", cve.id, version, affected_range, exc)
            return True
    return False


# ── Engine requirement checks


# Engine keys whose versions and requirements are both npm semver. Limited to what OSS IQ can
# actually check: `node` and `npm` are both probed. pnpm and yarn are deliberately absent — OSS IQ
# has no adapter for either, so nothing probes them and a declared floor for one would be checked
# on some runs and not others. When pnpm support lands, it is one entry here plus a probe.
NPM_SEMVER_ENGINES: frozenset[str] = frozenset({"node", "nodejs", "npm"})


def engine_version_satisfies_requirement(
    engine_key: str,
    context_version: str,
    requirement: str,
) -> bool:
    """Return True if *context_version* satisfies a package's engine *requirement*.

    Dispatcher:
      - ``"python"``                      -> PEP 440 ``PypiVersionRange``
      - ``"node"`` / ``"nodejs"``         -> npm semver range
      - ``"npm"`` / ``"pnpm"`` / ``"yarn"`` -> npm semver range

    Unknown engine keys pass through as True — an engine nobody can check must not read as a
    conflict. The package managers were previously in that bucket, so an `engines.npm` requirement
    was silently unenforced however far the installed CLI was from it.
    """
    try:
        if engine_key == "python":
            return pypi_version_satisfies_specifier(context_version, requirement)
        if engine_key in NPM_SEMVER_ENGINES:
            return npm_version_satisfies_range(context_version, requirement)
    except (ValueError, InvalidVersionRange, InvalidConstraintsError):
        pass
    return True


def stricter_engine_floor(engine_key: str, detected: str, declared: str) -> str:
    """Return whichever of *detected* / *declared* an engine requirement is likelier to fail against.

    Engine requirements are lower bounds in practice (``>=3.12``, ``>=18``), so the binding version
    is the lower of the two: a project promising support down to Python 3.11 breaks for its 3.11
    users however new the interpreter this scan happens to run on.

    Ordering is decided by `engine_version_satisfies_requirement` rather than a second comparator,
    so each ecosystem keeps its own rules, and a version it cannot parse resolves to *declared* —
    the bound that does not depend on whatever this machine happens to have installed.
    """
    if engine_version_satisfies_requirement(engine_key, detected, f">={declared}"):
        return declared
    return detected


def engine_mismatch_reason(
    runtime_requirements: dict[str, str] | None,
    engine_context: dict[str, str],
) -> str | None:
    """Return why *runtime_requirements* conflict with *engine_context*, or None if they don't.

    The single definition of the engine check: `has_engine_mismatch` (the solver's L2 clauses),
    `engine_compatibility`, and `service.project.strategy`'s engine gate all derive from it, so a
    candidate the gate rejects can never disagree with the verdict written onto the record.

    The returned string is user-facing — it reaches `ScanRecord.rejected_candidates` and from there
    console, export and agent output. None whenever either side is empty: absence of evidence, not
    evidence of compatibility.
    """
    if not runtime_requirements or not engine_context:
        return None
    for engine_key, context_version in engine_context.items():
        required = runtime_requirements.get(engine_key)
        if required and not engine_version_satisfies_requirement(engine_key, context_version, required):
            return f"requires {engine_key} {required}, checked against {context_version}"
    return None


def engine_compatibility(
    runtime_requirements: dict[str, str] | None,
    engine_context: dict[str, str],
) -> bool | None:
    """Tri-state engine verdict: False on conflict, True when checked and clear, None for no evidence.

    None means the question was never answerable — the release declares no runtime requirement, or
    nothing was detected/declared to check it against. Never read None as compatible.
    """
    if not runtime_requirements or not engine_context:
        return None
    return engine_mismatch_reason(runtime_requirements, engine_context) is None


def has_engine_mismatch(cv: CandidateVersion, engine_context: dict[str, str]) -> bool:
    """Return True if any declared runtime requirement in *cv* is incompatible with *engine_context*.

    *engine_context* maps engine key (e.g. ``"python"``, ``"node"``) to the version that engine is
    held to — the stricter of what was probed and what the manifest declares, see
    `service.project.runtime_context`.  Returns False when either side is empty.
    """
    return engine_mismatch_reason(cv.runtime_requirements, engine_context) is not None
