"""Module-system and API-break detection: what makes `latest_compatible_major` diverge from
`latest_in_major`.

Reads only the per-version `module_system` npm already populates. PyPI has no equivalent signal, so
every function here is a no-op for it until a remote API-break registry exists.
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


NODE_REQUIRE_ESM_MIN_STABLE = {20: "20.19.0", 22: "22.12.0"}
"""First release per Node line with require(esm) unflagged (https://nodejs.org/en/blog/release/v22.12.0,
backported to 20.x). 21.x is absent deliberately: EOL, no confirmed backport."""

NODE_REQUIRE_ESM_UNIVERSAL_FROM = 23
"""First Node line unflagged in its own .0.0, so needing no entry above. Kept separate from that
table's keys: a backport entry added later must not move this ceiling."""


def node_supports_require_esm(node_version: str | None) -> bool:
    """Whether this Node version can require() a synchronous ES module without a loader flag.

    Pass the floor the project must support, not the newest release installed. Necessary but not
    sufficient: no static manifest field records whether the target's ESM build uses top-level
    `await`, which fails under require() on any runtime.
    """
    if not node_version:
        return False
    try:
        parsed = semver.Version.parse(pad_npm_version(node_version))
    except ValueError:
        return False
    minimum = NODE_REQUIRE_ESM_MIN_STABLE.get(parsed.major)
    if minimum is None:
        return parsed.major >= NODE_REQUIRE_ESM_UNIVERSAL_FROM
    return parsed >= semver.Version.parse(minimum)


def breaking_majors(
    package_name: str,
    releases: list[PackageVersion],
    registry: ProjectPackagesRegistry,
    *,
    node_version: str | None = None,
) -> dict[tuple[int, int], str]:
    """Return {major_key: note} for every major line flagged as a known break.

    A major is flagged only when *every* release in it is ESM_ONLY, so one that later dual-published
    a patch, or has any release with no module_system, stays unflagged.

    Args:
        package_name: Reserved for a future API-break registry lookup; unused.
        node_version: The project's Node floor; an ESM-only major is not flagged when this runtime
            can require() ESM directly.
    """
    buckets: dict[tuple[int, int], list[PackageVersion]] = defaultdict(list)
    for pv in releases:
        key = major_key(pv.version, registry)
        if key is not None:
            buckets[key].append(pv)

    node_covers_require_esm = registry == ProjectPackagesRegistry.NPM and node_supports_require_esm(node_version)

    flagged: dict[tuple[int, int], str] = {}
    for key, bucket in buckets.items():
        if not bucket or not all(pv.module_system == ModuleSystem.ESM_ONLY for pv in bucket):
            continue
        if node_covers_require_esm:
            continue
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
    node_version: str | None = None,
) -> str | None:
    """Newest release among majors >= installed's major that is not flagged breaking.

    Input is uncapped: with several clean majors between installed and the first known break, this
    reaches across all of them, not just the installed major (`latest_in_major`). None when nothing
    is reachable or the release data will not parse.
    """
    try:
        breaks = breaking_majors(package_name, releases_since_installed, registry, node_version=node_version)
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
    *,
    node_version: str | None = None,
) -> tuple[ModuleSystem | None, str | None]:
    """Return the target version's module system and a breaking-change note, if any.

    The note is None whenever the project itself is `"type": "module"` — an ESM-only dependency is
    not a break for an ESM project — or when `node_version` can require() the target directly.
    """
    target_release = next((pv for pv in releases if pv.version == target_version), None)
    target_module_system = target_release.module_system if target_release else None

    if project_declares_esm:
        return target_module_system, None

    target_major = major_key(target_version, registry)
    breaking_change = (
        breaking_majors(package_name, releases, registry, node_version=node_version).get(target_major)
        if target_major is not None
        else None
    )
    return target_module_system, breaking_change
