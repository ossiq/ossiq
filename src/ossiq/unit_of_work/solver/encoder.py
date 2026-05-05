from __future__ import annotations

import re

import semver  # type: ignore[import]
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name

from ossiq.unit_of_work.solver.driver import EncodedProblem
from ossiq.unit_of_work.solver.driver_pysat import VarAllocator
from ossiq.unit_of_work.solver.problem import CandidateVersion, SolverProblem
from ossiq.unit_of_work.solver.weights import W_DEPRECATED, W_ENGINE, W_VERY_FRESH, age_weight

_BARE_VERSION_RE = re.compile(r"^\d[\d.]*$")
_OPERATOR_VERSION_RE = re.compile(r"^([><=^~!]{1,2})\s*(\d[\d.]*)$")


def normalize_semver_partial(v: str) -> str:
    """Pad a partial version string to full semver: '14' → '14.0.0'."""
    parts = v.split(".")
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts[:3])


def match_semver_constraint(version: str, constraint: str) -> bool:
    """Match a version string against an npm/semver range constraint."""
    if "||" in constraint:
        return any(match_semver_constraint(version, part.strip()) for part in constraint.split("||"))

    try:
        candidate = semver.Version.parse(normalize_semver_partial(version))
    except ValueError:
        return True

    constraint = constraint.strip()

    if _BARE_VERSION_RE.match(constraint):
        # Treat bare version as caret range: ^X.Y.Z
        try:
            base = semver.Version.parse(normalize_semver_partial(constraint))
            upper = semver.Version(major=base.major + 1, minor=0, patch=0)
            return base <= candidate < upper
        except ValueError:
            return True

    m = _OPERATOR_VERSION_RE.match(constraint)
    if not m:
        return True

    op, ver_str = m.group(1), m.group(2)
    try:
        base = semver.Version.parse(normalize_semver_partial(ver_str))
    except ValueError:
        return True

    try:
        if op == "^":
            upper = semver.Version(major=base.major + 1, minor=0, patch=0)
            return base <= candidate < upper
        if op == "~":
            upper = semver.Version(major=base.major, minor=base.minor + 1, patch=0)
            return base <= candidate < upper
        return candidate.match(f"{op}{base}")
    except ValueError:
        return True


def version_matches(version: str, constraint: str | None) -> bool:
    """Return True if version satisfies constraint (PEP 440 or npm semver)."""
    if constraint is None:
        return True
    try:
        try:
            return version in SpecifierSet(constraint)
        except InvalidSpecifier:
            return match_semver_constraint(version, constraint)
    except Exception:
        return True


def engine_version_matches(engine_key: str, context_version: str, requirement: str) -> bool:
    """Return True if context_version satisfies the engine requirement."""
    try:
        if engine_key == "python":
            return context_version in SpecifierSet(requirement)
        if engine_key in ("node", "nodejs"):
            return match_semver_constraint(context_version, requirement)
    except Exception:
        pass
    return True


def has_engine_mismatch(cv: CandidateVersion, engine_context: dict[str, str]) -> bool:
    """Return True if any declared runtime requirement is incompatible with engine_context."""
    if not cv.runtime_requirements or not engine_context:
        return False
    for engine_key, context_version in engine_context.items():
        required = cv.runtime_requirements.get(engine_key)
        if required is None:
            continue
        if not engine_version_matches(engine_key, context_version, required):
            return True
    return False


def _ladder_amo(eligible_vids: list[int], alloc: VarAllocator) -> list[list[int]]:
    """Return hard clauses enforcing At-Most-One over eligible_vids using ladder encoding.

    Uses the Sinz (2005) sequential-counter encoding: n-1 auxiliary variables and
    3n-4 clauses (linear), replacing the O(n²) pairwise encoding.
    """
    n = len(eligible_vids)
    if n <= 1:
        return []
    s = [alloc.allocate_fresh() for _ in range(n - 1)]
    x = eligible_vids
    clauses: list[list[int]] = [[-x[0], s[0]], [-x[n - 1], -s[n - 2]]]
    for i in range(1, n - 1):
        clauses.extend([[-x[i], s[i]], [-x[i], -s[i - 1]], [-s[i - 1], s[i]]])
    return clauses


class ConstraintEncoder:
    """Translates a SolverProblem into an EncodedProblem (hard + soft WCNF clauses)."""

    def __init__(self, penalize_fresh_days: int = 0) -> None:
        """Configure the encoder.

        Args:
            penalize_fresh_days: When > 0, candidate versions with age_days < this value
                                 receive a W_VERY_FRESH (1M) soft penalty (L6). Default 0 disables L6.
        """
        self._penalize_fresh_days = penalize_fresh_days

    def encode(self, problem: SolverProblem) -> EncodedProblem:
        """Encode a SolverProblem into hard and soft clauses for the MaxSAT solver.

        Three-pass encoding:
        1. Allocate all SAT variables (enables inter-package implication lookup in pass 3).
        2. Emit per-package hard (L1, L5, AMO, ALO) and soft (L2, L3, L4, L6) clauses.
        3. Emit inter-package implication clauses from CandidateVersion.requires.
        """
        alloc = VarAllocator()
        hard_clauses: list[list[int]] = []
        soft_clauses: list[tuple[int, list[int]]] = []
        var_map: dict[int, tuple[str, str]] = {}

        # pkg_state: pkg → (candidates, all_vids, eligible_vids, eligible_set)
        # eligible_vids/eligible_set populated in pass 2.
        pkg_state: dict[str, tuple[tuple[CandidateVersion, ...], list[int], list[int], set[int]]] = {}

        # Pass 1: Allocate all variables
        for constraint in problem.constraints:
            pkg = constraint.package_name
            candidates = problem.candidates.get(pkg, ())
            if not candidates:
                continue
            all_vids: list[int] = []
            for cv in candidates:
                vid = alloc.allocate(pkg, cv.version)
                var_map[vid] = (pkg, cv.version)
                all_vids.append(vid)
            pkg_state[pkg] = (candidates, all_vids, [], set())

        # Pass 2: Per-package hard and soft clauses
        for constraint in problem.constraints:
            pkg = constraint.package_name
            if pkg not in pkg_state:
                continue
            candidates, all_vids, _, _ = pkg_state[pkg]

            # L1 + L5: forbid out-of-constraint and CVE-affected versions
            eligible_vids: list[int] = []
            for cv, vid in zip(candidates, all_vids, strict=True):
                if not version_matches(cv.version, constraint.version_constraint):
                    hard_clauses.append([-vid])  # L1 constraint mismatch
                elif cv.has_cve:
                    hard_clauses.append([-vid])  # L5 CVE hard-forbidden
                else:
                    eligible_vids.append(vid)

            eligible_set = set(eligible_vids)
            pkg_state[pkg] = (candidates, all_vids, eligible_vids, eligible_set)

            # Structural: ladder AMO + ALO over eligible candidates
            hard_clauses.extend(_ladder_amo(eligible_vids, alloc))
            if eligible_vids:
                hard_clauses.append(list(eligible_vids))  # ALO; skip if empty (UNSAT by design)

            # Soft clauses — eligible candidates only
            for cv, vid in zip(candidates, all_vids, strict=True):
                if vid not in eligible_set:
                    continue
                if has_engine_mismatch(cv, problem.engine_context):
                    soft_clauses.append((W_ENGINE, [-vid]))  # L2
                soft_clauses.append((age_weight(cv.age_days), [vid]))  # L3
                if cv.is_deprecated:
                    soft_clauses.append((W_DEPRECATED, [-vid]))  # L4
                # L6: very fresh — strongly discourage supply-chain risks
                if (
                    self._penalize_fresh_days > 0
                    and cv.age_days is not None
                    and cv.age_days < self._penalize_fresh_days
                ):
                    soft_clauses.append((W_VERY_FRESH, [-vid]))
                # L7: health score — reserved, not implemented

        # Pass 3: Inter-package implication clauses from CandidateVersion.requires
        for constraint in problem.constraints:
            pkg = constraint.package_name
            if pkg not in pkg_state:
                continue
            candidates, all_vids, _, eligible_set = pkg_state[pkg]

            for cv, vid in zip(candidates, all_vids, strict=True):
                if vid not in eligible_set or cv.requires is None:
                    continue
                for dep_pkg_raw, dep_constraint in cv.requires.items():
                    dep_pkg = canonicalize_name(dep_pkg_raw)
                    if dep_pkg not in pkg_state:
                        continue  # dependency not in this problem — skip
                    dep_candidates, dep_all_vids, _, dep_eligible_set = pkg_state[dep_pkg]
                    compatible = [
                        dep_vid
                        for dep_cv, dep_vid in zip(dep_candidates, dep_all_vids, strict=True)
                        if dep_vid in dep_eligible_set and version_matches(dep_cv.version, dep_constraint)
                    ]
                    if not compatible:
                        continue  # no satisfying candidate — skip conservatively
                    hard_clauses.append([-vid] + compatible)  # implication: A@v → ∃ compatible B

        return EncodedProblem(
            hard_clauses=hard_clauses,
            soft_clauses=soft_clauses,
            var_map=var_map,
        )
