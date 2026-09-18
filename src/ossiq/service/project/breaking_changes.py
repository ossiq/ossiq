"""Module-system and API-break detection: what makes `latest_compatible_major` diverge from
`latest_in_major` (item 1's ladder rung).

Sibling to `ladder.py`, same "pure function over data already in hand" shape: no new HTTP calls,
just the per-version `module_system` npm already populates (see `adapters.api_npm`). PyPI has no
analogous machine-readable signal and is currently a no-op here — a bundled curated JSON list was
tried and dropped as unmaintainable at any real scale; the intended replacement is a remote
API-break registry (scalable, updatable independently of a release), not reintroducing a static
list. `breaking_majors`'s `package_name` parameter is kept for that future lookup.
"""

from collections import defaultdict
from datetime import datetime

import semver

from ossiq.adapters.api_interfaces import VersionRules
from ossiq.domain.common import ModuleSystem, ProjectPackagesRegistry
from ossiq.domain.version import PackageVersion, pad_npm_version
from ossiq.service.project.ladder import installable_releases
from ossiq.solver.version_matchers import major_key


def npm_sort_key(version: str) -> semver.Version:
    """Parse an npm version for ordering, tolerating missing minor/patch segments."""
    return semver.Version.parse(pad_npm_version(version))


def breaking_majors(
    package_name: str,
    releases: list[PackageVersion],
    registry: ProjectPackagesRegistry,
) -> dict[tuple[int, int], str]:
    """Return {major_key: note} for every major line flagged as a known break.

    npm: a major is flagged only when *every* release in that major's bucket (via
    solver.version_matchers.major_key, the same helper ladder.py already uses) is
    ModuleSystem.ESM_ONLY — a major that later dual-published a patch is not flagged, and a bucket
    with any unparseable/absent module_system is conservatively left unflagged. PyPI: always {} for
    now — no per-release machine-readable signal exists (unlike npm's `exports` map), and the
    static curated list this used to consult was unmaintainable at any real scale. `package_name`
    is kept in the signature for a future remote API-break registry lookup, not used yet.
    """
    buckets: dict[tuple[int, int], list[PackageVersion]] = defaultdict(list)
    for pv in releases:
        key = major_key(pv.version, registry)
        if key is not None:
            buckets[key].append(pv)

    flagged: dict[tuple[int, int], str] = {}
    for key, bucket in buckets.items():
        if bucket and all(pv.module_system == ModuleSystem.ESM_ONLY for pv in bucket):
            since = min(bucket, key=lambda pv: npm_sort_key(pv.version))
            flagged[key] = f"ESM-only from {since.version}"
    return flagged


def compute_latest_compatible_major(
    package_name: str,
    releases_since_installed: list[PackageVersion],
    installed_version: str,
    version_rules: VersionRules,
    registry: ProjectPackagesRegistry,
    *,
    now: datetime | None = None,
) -> str | None:
    """Newest release among majors >= installed's major that is not flagged breaking.

    Uncapped input, same as `ladder.compute_version_ladder` takes — a package can have several
    clean majors between "installed" and "known break," in which case this is the newest release
    among those, not merely the newest release in the installed major (`latest_in_major`).
    """
    try:
        breaks = breaking_majors(package_name, releases_since_installed, registry)
        installed_major = major_key(installed_version, registry)
        reachable = [
            pv
            for pv in installable_releases(releases_since_installed, version_rules, now=now)
            if (mk := major_key(pv.version, registry)) is not None
            and (installed_major is None or mk >= installed_major)
            and mk not in breaks
        ]
        newest = version_rules.newest_version(reachable)
        return newest.version if newest else None
    except (ValueError, TypeError):
        # Mirrors compute_version_ladder's own fallback: a registry-specific compare_versions/
        # major_key call choked on unparseable data somewhere in the release list.
        return None


def module_system_label(
    package_name: str,
    installed_version: str,
    target_version: str,
    releases: list[PackageVersion],
    registry: ProjectPackagesRegistry,
    project_declares_esm: bool,
) -> tuple[ModuleSystem | None, str | None]:
    """(target's own module_system, breaking_change note or None).

    breaking_change is None whenever project_declares_esm is True, regardless of the target's own
    module_system — an ESM-only dependency is not a break for a project that is itself
    `"type": "module"`.
    """
    target_release = next((pv for pv in releases if pv.version == target_version), None)
    target_module_system = target_release.module_system if target_release else None

    if project_declares_esm:
        return target_module_system, None

    target_major = major_key(target_version, registry)
    breaking_change = (
        breaking_majors(package_name, releases, registry).get(target_major) if target_major is not None else None
    )
    return target_module_system, breaking_change
