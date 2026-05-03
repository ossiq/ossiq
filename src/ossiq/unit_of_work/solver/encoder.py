from __future__ import annotations

import re

import semver  # type: ignore[import]
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from ossiq.unit_of_work.solver.driver import EncodedProblem
from ossiq.unit_of_work.solver.driver_pysat import VarAllocator
from ossiq.unit_of_work.solver.problem import CandidateVersion, SolverProblem
from ossiq.unit_of_work.solver.weights import W_DEPRECATED, W_ENGINE, age_weight

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


class ConstraintEncoder:
    """Translates a SolverProblem into an EncodedProblem (hard + soft WCNF clauses)."""

    def encode(self, problem: SolverProblem) -> EncodedProblem:
        """Encode a SolverProblem into hard and soft clauses for the MaxSAT solver."""
        alloc = VarAllocator()
        hard_clauses: list[list[int]] = []
        soft_clauses: list[tuple[int, list[int]]] = []
        var_map: dict[int, tuple[str, str]] = {}

        for constraint in problem.constraints:
            pkg = constraint.package_name
            candidates = problem.candidates.get(pkg, ())

            if not candidates:
                continue

            # Allocate vars for all candidates
            all_vids: list[int] = []
            for cv in candidates:
                vid = alloc.allocate(pkg, cv.version)
                var_map[vid] = (pkg, cv.version)
                all_vids.append(vid)

            # L1 Hard: forbid versions outside the declared constraint
            eligible_vids: list[int] = []
            for cv, vid in zip(candidates, all_vids, strict=True):
                if version_matches(cv.version, constraint.version_constraint):
                    eligible_vids.append(vid)
                else:
                    hard_clauses.append([-vid])

            # Structural: AMO (pairwise) + ALO over eligible candidates
            if len(eligible_vids) >= 2:
                for i in range(len(eligible_vids)):
                    for j in range(i + 1, len(eligible_vids)):
                        hard_clauses.append([-eligible_vids[i], -eligible_vids[j]])
            if eligible_vids:
                hard_clauses.append(list(eligible_vids))  # ALO; skip if empty (UNSAT by design)

            # Soft clauses — eligible candidates only
            eligible_set = set(eligible_vids)
            for cv, vid in zip(candidates, all_vids, strict=True):
                if vid not in eligible_set:
                    continue
                if has_engine_mismatch(cv, problem.engine_context):
                    soft_clauses.append((W_ENGINE, [-vid]))  # L2
                soft_clauses.append((age_weight(cv.age_days), [vid]))  # L3
                if cv.is_deprecated:
                    soft_clauses.append((W_DEPRECATED, [-vid]))  # L4
                # L5: health score — reserved, not implemented

        return EncodedProblem(
            hard_clauses=hard_clauses,
            soft_clauses=soft_clauses,
            var_map=var_map,
        )
