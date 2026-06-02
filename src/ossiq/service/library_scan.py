"""
Constraint resolution for library projects that ship without a lockfile.

Libraries declare version ranges (e.g. ^4.18.0) rather than pinned versions.
`resolve_library_constraints` enriches a no-lockfile Project by replacing each
dep's version_installed (currently the normalised lower bound of the range) with
the latest published version that still satisfies the declared constraint. This
prevents the solver from producing within-range noise recommendations and ensures
only cross-major updates that require a constraint edit are surfaced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import semver
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion as PackagingInvalidVersion
from packaging.version import Version as PackagingVersion

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.project import Dependency, Project
from ossiq.domain.version import normalize_version

_BARE_SEMVER = re.compile(r"^v?\d+(\.\d+){0,2}([.-][a-zA-Z0-9._-]+)*$")


def _parse(v: str) -> semver.Version:
    parts = v.split(".")
    while len(parts) < 3:
        parts.append("0")
    return semver.Version.parse(".".join(parts[:3]))


def _max_stable(versions: list[str]) -> str:
    stable = [v for v in versions if _parse(v).prerelease is None]
    candidates = stable or versions
    return str(max(candidates, key=_parse))


def _max_pep440(versions: list[str]) -> str | None:
    """Return the highest PEP 440 version string from *versions*, or None if none parse."""
    parsed: list[tuple[PackagingVersion, str]] = []
    for v in versions:
        try:
            parsed.append((PackagingVersion(v), v))
        except PackagingInvalidVersion:
            pass
    return max(parsed, key=lambda pair: pair[0])[1] if parsed else None


def latest_version_for_constraint(versions: list[str], constraint: str) -> str:
    """Return the latest version from *versions* that satisfies *constraint*.

    Handles the common npm constraint prefixes (^, ~) and bare semver pins.
    Falls back to normalize_version(constraint) for complex or unrecognised forms.
    """
    if not versions:
        return normalize_version(constraint)

    s = constraint.strip()

    if not s or s in ("*", "latest"):
        return _max_stable(versions)

    if s.startswith("^"):
        try:
            base = _parse(s[1:])
            candidates = [v for v in versions if _parse(v).major == base.major and _parse(v) >= base]
            return str(max(candidates, key=_parse)) if candidates else s[1:]
        except ValueError:
            return normalize_version(constraint)

    if s.startswith("~") and not s.startswith("~="):
        try:
            base = _parse(s[1:])
            candidates = [
                v
                for v in versions
                if _parse(v).major == base.major and _parse(v).minor == base.minor and _parse(v) >= base
            ]
            return str(max(candidates, key=_parse)) if candidates else s[1:]
        except ValueError:
            return normalize_version(constraint)

    if _BARE_SEMVER.fullmatch(s):
        return s

    try:
        spec = SpecifierSet(s)
        filtered = list(spec.filter(versions, prereleases=False))
        if filtered:
            result = _max_pep440(filtered)
            if result:
                return result
    except InvalidSpecifier:
        pass

    return normalize_version(constraint)


@dataclass(frozen=True)
class UpgradePath:
    """A cross-constraint upgrade opportunity for a direct dependency in a library project."""

    package_name: str
    current_constraint: str
    latest_in_range: str
    latest_available: str
    suggested_constraint: str


def compute_upgrade_paths(
    project: Project,
    registry: AbstractPackageRegistryApi,
) -> list[UpgradePath]:
    """Return constraint widening opportunities for a no-lockfile project.

    For each direct dependency (production and optional), compares the latest version
    satisfying the declared constraint (version_installed, enriched by
    resolve_library_constraints) against the registry's absolute latest stable release.
    Where the latest available is outside the current range, emits an UpgradePath with
    a suggested updated constraint.

    Returns an empty list if the project has a lockfile or no widening is needed.
    Must be called after resolve_library_constraints so version_installed reflects
    the true latest-in-range, not the lower-bound fallback.
    """
    if project.has_lockfile:
        return []

    all_deps: dict[str, Dependency] = {
        **project.dependency_tree.dependencies,
        **project.dependency_tree.optional_dependencies,
    }
    deps_with_constraint = {name: dep for name, dep in all_deps.items() if dep.version_defined}
    if not deps_with_constraint:
        return []

    try:
        packages = registry.packages_info_batch(list(deps_with_constraint.keys()))
    except Exception:
        return []

    paths: list[UpgradePath] = []
    for name, dep in deps_with_constraint.items():
        try:
            version_defined = dep.version_defined
            if not version_defined:
                continue
            pkg = packages.get(name)
            if not pkg or not pkg.latest_version:
                continue
            latest_available = pkg.latest_version
            suggested = registry.rewrite_specifier(version_defined, latest_available)
            if not suggested or suggested == version_defined:
                continue
            paths.append(
                UpgradePath(
                    package_name=dep.canonical_name,
                    current_constraint=version_defined,
                    latest_in_range=dep.version_installed,
                    latest_available=latest_available,
                    suggested_constraint=suggested,
                )
            )
        except Exception:
            continue

    return paths


def resolve_library_constraints(project: Project, registry: AbstractPackageRegistryApi) -> Project:
    """Enrich a no-lockfile Project with registry-resolved version_installed values.

    For each direct dependency, replaces the normalised lower-bound version
    (e.g. "4.18.0" from "^4.18.0") with the latest published version that still
    satisfies the declared constraint (e.g. "4.21.2"). This prevents the solver
    from recommending updates that would not require any change to package.json.

    Returns the project unchanged when:
    - the project has a lockfile (enrichment is not needed)
    - the registry call fails (graceful degradation)
    - a dep has no version_defined to resolve against
    """
    if project.has_lockfile:
        return project

    all_deps: dict[str, Dependency] = {
        **project.dependency_tree.dependencies,
        **project.dependency_tree.optional_dependencies,
    }
    if not all_deps:
        return project

    try:
        registry.packages_info_batch(list(all_deps.keys()))
    except Exception:
        return project

    for name, dep in all_deps.items():
        if not dep.version_defined:
            continue
        try:
            versions = [str(pv.version) for pv in registry.package_versions(name) if not pv.is_prerelease]
        except Exception:
            continue
        if not versions:
            continue
        dep.version_installed = latest_version_for_constraint(versions, dep.version_defined)

    return project
