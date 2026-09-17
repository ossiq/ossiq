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
        │               └─ univers.NpmVersionRange / SemverVersion
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

import logging
import operator
import re

import semver
from packaging.version import InvalidVersion
from packaging.version import Version as PackagingVersion
from univers.version_constraint import InvalidConstraintsError
from univers.version_range import InvalidVersionRange, NpmVersionRange, PypiVersionRange
from univers.versions import PypiVersion, SemverVersion

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.solver.problem import CandidateVersion

logger = logging.getLogger(__name__)


# ── npm / Node.js semver
# Spec: https://github.com/npm/node-semver#versions

# Standard semver prerelease/build metadata regex
# Matches `-` or `+` followed by alphanumeric chars, dots, or hyphens.
SEMVER_METADATA_RE = re.compile(r"[-+][0-9A-Za-z-\.]+")

NOT_EQUAL_RE = re.compile(r"^!=\s*(.+)$")
# A *partial* bare version - "14" or "14.2" - needs manual caret-expansion below: univers's
# NpmVersionRange resolves a partial bare version to that exact (zero-padded) version rather
# than the whole major/minor line the node-semver spec calls for ("14" should match every
# 14.x.y). A *full* bare version like "4.17.1" does NOT have this problem and must NOT be
# caret-expanded: per the node-semver spec, a comparator with no operator means equality
# ("If no operator is specified, then equality is assumed"), and univers already resolves a
# bare full version to exactly that version on its own. Matching 3+ component bare versions
# here as well was a real bug (OSS IQ defect report B3): a package.json exact pin such as
# "express": "4.17.1" was silently treated as "^4.17.1" (anything below 5.0.0), which is why
# npm's solver looked like it could move past a pin PyPI's exact-pin parsing correctly refused.
PARTIAL_BARE_VERSION_RE = re.compile(r"^\d+(\.\d+)?([-+][0-9A-Za-z-\.]+)?$")

# Mapping string operators to standard Python math operators
OPS = {
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
    "=": operator.eq,
    "==": operator.eq,
    "!=": operator.ne,
}
# Matches a prerelease suffix on a full version: "3.0.0-0" / "3.0.0-rc.1" -> strip to "3.0.0".
# univers rejects prerelease-floor constraints like ">=3.0.0-0"; we deliberately ignore
# prerelease precision. Hyphen ranges ("1.2.3 - 2.0.0") are unaffected: they have spaces.
PRERELEASE_SUFFIX_RE = re.compile(r"(\d+\.\d+\.\d+)-[0-9A-Za-z][0-9A-Za-z.-]*")


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


def _fallback_evaluate_bounds(version_obj: SemverVersion, constraint_string: str) -> bool:
    """
    Manually evaluates constraint branches mathematically when strict semver
    parsers (like univers) crash on overlapping or redundant prerelease boundaries.
    """
    # Split the constraint into OR branches (||)
    for branch in (b.strip() for b in constraint_string.split("||")):
        clauses = re.sub(r"([><=~^!]+)\s+", r"\1", branch).split()
        branch_satisfied = True

        for clause in clauses:
            match = re.match(r"^([><=~^!]+)?(.*)$", clause)
            if not match:
                continue

            op_str, constraint_val = match.groups()
            op_str = op_str or "="

            try:
                if op_str in OPS and not OPS[op_str](version_obj, SemverVersion(constraint_val)):  # type: ignore
                    branch_satisfied = False
                    break
            except ValueError:
                continue

        if branch_satisfied:
            return True

    return False


def npm_version_satisfies_range(version: str, range_constraint: str, allow_beta: bool = False) -> bool:
    """Return True if *version* satisfies an npm semver *range_constraint*.

    Implements a subset of the node-semver range syntax:
      - ``||`` union  — "14 || 16"
      - ``^``  caret  — "^1.2.3"  compatible with the same major
      - ``~``  tilde  — "~1.2.3"  compatible with the same minor
      - bare partial version  — "14" or "14.2"  treated as a caret range (^14.0.0 / ^14.2.0)
      - bare full version  — "4.17.1"  exact match only (no operator = equality, per spec)
      - comparison operators  — ">", ">=", "<", "<=", "=", "!="
      - npm alias  — "npm:pkg@^1.2.3"  matched against the embedded range
    """
    if not allow_beta and "-" in version:
        return False

    constraint = strip_npm_alias(range_constraint).strip()

    m = NOT_EQUAL_RE.match(constraint)
    if m:
        try:
            return SemverVersion(version) != SemverVersion(m.group(1))  # type: ignore
        except ValueError:
            return True

    parts = [p.strip() for p in constraint.split("||")]
    processed = " || ".join(f"^{p}" if PARTIAL_BARE_VERSION_RE.match(p) else p for p in parts)

    try:
        return SemverVersion(version) in NpmVersionRange.from_native(processed)  # type: ignore
    except InvalidConstraintsError:
        try:
            return _fallback_evaluate_bounds(SemverVersion(version), processed)  # type: ignore
        except ValueError:
            return True
    except ValueError as exc:
        logger.debug(
            "npm_version_satisfies_range: unparseable version=%r constraint=%r error=%s", version, range_constraint, exc
        )
        return True


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
        parts = version.split(".")
        while len(parts) < 3:
            parts.append("0")
        return (0, semver.Version.parse(".".join(parts[:3])).major)
    except (InvalidVersion, ValueError):
        return None


def satisfies_all_constraints(version: str, constraints: list[str], registry: ProjectPackagesRegistry) -> bool:
    """Return True when version satisfies every non-empty constraint in the list."""
    return all(version_satisfies_constraint(version, c, registry) for c in constraints if c)


# ── Engine requirement checks


def engine_version_satisfies_requirement(
    engine_key: str,
    context_version: str,
    requirement: str,
) -> bool:
    """Return True if the running *context_version* satisfies a package's engine *requirement*.

    Dispatcher:
      - ``"python"``           -> PEP 440 ``PypiVersionRange``
      - ``"node"`` / ``"nodejs"`` -> npm semver range

    Unknown engine keys pass through as True.
    """
    try:
        if engine_key == "python":
            return pypi_version_satisfies_specifier(context_version, requirement)
        if engine_key in ("node", "nodejs"):
            return npm_version_satisfies_range(context_version, requirement)
    except (ValueError, InvalidVersionRange, InvalidConstraintsError):
        pass
    return True


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
            return f"requires {engine_key} {required}, detected {context_version}"
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

    *engine_context* maps engine key (e.g. ``"python"``, ``"node"``) to the
    currently running version string.  Returns False when either side is empty.
    """
    return engine_mismatch_reason(cv.runtime_requirements, engine_context) is not None
