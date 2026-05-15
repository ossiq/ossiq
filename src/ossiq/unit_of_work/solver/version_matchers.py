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
import re

from univers.version_range import NpmVersionRange, PypiVersionRange
from univers.versions import PypiVersion, SemverVersion

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.unit_of_work.solver.problem import CandidateVersion

logger = logging.getLogger(__name__)


# ── npm / Node.js semver
# Spec: https://github.com/npm/node-semver#versions

# Matches a bare version with no operator: "14", "1.2", "1.2.3"
_BARE_VERSION_RE = re.compile(r"^\d[\d.]*$")

# Matches npm != operator: "!=1.0.0" — univers does not handle != for npm ranges
_NOT_EQUAL_RE = re.compile(r"^!=\s*(\d[\d.]*)$")


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


def npm_version_satisfies_range(version: str, range_constraint: str) -> bool:
    """Return True if *version* satisfies an npm semver *range_constraint*.

    Implements a subset of the node-semver range syntax:
      - ``||`` union  — "14 || 16"
      - ``^``  caret  — "^1.2.3"  compatible with the same major
      - ``~``  tilde  — "~1.2.3"  compatible with the same minor
      - bare version  — "14"  treated as a caret range (^14.0.0)
      - comparison operators  — ">", ">=", "<", "<=", "=", "!="

    An unparseable version or constraint passes through as True so that an
    unknown format never becomes a hard block.
    """
    constraint = range_constraint.strip()

    m = _NOT_EQUAL_RE.match(constraint)
    if m:
        try:
            return SemverVersion(version) != SemverVersion(m.group(1))  # type: ignore
        except Exception:
            return True

    # Expand bare versions to caret ranges per || branch before delegating to univers.
    # univers handles || natively but treats bare "14" as exact =14.0.0, not ^14.
    parts = [p.strip() for p in constraint.split("||")]
    processed = " || ".join(f"^{p}" if _BARE_VERSION_RE.match(p) else p for p in parts)

    try:
        return SemverVersion(version) in NpmVersionRange.from_native(processed)  # type: ignore
    except Exception as exc:
        logger.debug(
            "npm_version_satisfies_range: unparseable version=%r constraint=%r error=%s",
            version,
            range_constraint,
            exc,
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
    except Exception as exc:
        logger.debug(
            "version_satisfies_constraint: parse failed version=%r constraint=%r registry=%s error=%s",
            version,
            constraint,
            registry,
            exc,
        )
        return True


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
    except Exception:
        pass
    return True


def has_engine_mismatch(cv: CandidateVersion, engine_context: dict[str, str]) -> bool:
    """Return True if any declared runtime requirement in *cv* is incompatible with *engine_context*.

    *engine_context* maps engine key (e.g. ``"python"``, ``"node"``) to the
    currently running version string.  Returns False when either side is empty.
    """
    if not cv.runtime_requirements or not engine_context:
        return False
    for engine_key, context_version in engine_context.items():
        required = cv.runtime_requirements.get(engine_key)
        if required is None:
            continue
        if not engine_version_satisfies_requirement(engine_key, context_version, required):
            return True
    return False
