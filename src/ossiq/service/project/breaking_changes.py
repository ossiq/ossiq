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


def crosses_module_system(
    installed: ModuleSystem | None, candidate: ModuleSystem | None, project_declares_esm: bool
) -> bool:
    """Whether code that loads the installed release could stop loading the candidate.

    The one definition of a module-system break, shared by the strategy's gate and the ladder's
    `latest_preserving_module_system`, so the two can never disagree. Only a move *to* ESM-only
    breaks: CJS and dual releases load from either side. An installed release with no known module
    system is treated as CommonJS, npm's default without `"type": "module"`, while an ESM-only
    installed release means the project already copes with ESM for this package.
    """
    if project_declares_esm or installed == ModuleSystem.ESM_ONLY:
        return False
    return candidate == ModuleSystem.ESM_ONLY


def module_break_reason(
    release: PackageVersion, releases: list[PackageVersion], registry: ProjectPackagesRegistry
) -> str:
    """Name the break as "ESM-only from <first ESM-only release of that major>".

    Anchored on the major's first ESM-only release so every gated release of one major carries the
    same reason, the text `rejected_candidates` and `breaking_change` have always used.
    """
    major = major_key(release.version, registry)
    same_major_esm = [
        pv
        for pv in releases
        if pv.module_system == ModuleSystem.ESM_ONLY
        and not pv.is_unpublished
        and not pv.is_yanked
        and major_key(pv.version, registry) == major
    ]
    since = min(same_major_esm, key=lambda pv: npm_sort_key(pv.version), default=release)
    return f"ESM-only from {since.version}"


def esm_interop_note(node_version: str | None) -> str:
    """Say what the runtime means for loading an ESM-only release from CommonJS code.

    Pass the Node the scan checked against: the provided or probed runtime, held to the project's
    declared floor.
    """
    if not node_version:
        return "ESM-only: runtime unknown, so whether require() can load it is unverified"
    if node_supports_require_esm(node_version):
        return (
            f"ESM-only: require() on Node {node_version} returns the module namespace, so it works "
            "only if the package has named exports; a default-export-only package still breaks"
        )
    return f"ESM-only: won't load via require() on Node {node_version}"


def breaking_majors(
    package_name: str,
    releases: list[PackageVersion],
    registry: ProjectPackagesRegistry,
    *,
    node_version: str | None = None,
) -> dict[tuple[int, int], str]:
    """Return {major_key: note} for every major line flagged as a known break.

    A major is flagged only when *every* published release in it is ESM_ONLY, so one that later
    dual-published a patch, or has any release with no module_system, stays unflagged.

    Runtime-aware on purpose: this backs `latest_compatible_major`, the alternative a
    `require(esm)`-capable runtime could reach. The recommendation's own gate is
    `crosses_module_system`, which ignores the runtime.

    Args:
        package_name: Reserved for a future API-break registry lookup; unused.
        node_version: The project's Node floor; an ESM-only major is not flagged when this runtime
            can require() ESM directly.
    """
    buckets: dict[tuple[int, int], list[PackageVersion]] = defaultdict(list)
    for pv in releases:
        # A pulled release (chalk@5.6.1, unpublished after the September 2025 compromise) survives
        # only as a `time`-map tombstone with no module_system; counting it unflagged its whole
        # ESM-only major, so nobody could install the one release that made the major "mixed".
        if pv.is_unpublished or pv.is_yanked:
            continue
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


def compute_latest_preserving_module_system(
    releases_since_installed: list[PackageVersion],
    installed_version: str,
    installed_module_system: ModuleSystem | None,
    version_rules: VersionRules,
    project_declares_esm: bool,
    *,
    now: datetime | None = None,
) -> str | None:
    """Newest installable release that code on the installed module system can still load.

    Runtime-independent, unlike `latest_compatible_major`: it is where every tier below `latest`
    stops, and where `latest` stops too unless the runtime can `require()` ESM. Equals
    `installed_version` when nothing newer qualifies; None when the release data will not parse.
    """
    try:
        loadable = [
            pv
            for pv in installable_releases(releases_since_installed, version_rules, now=now)
            if not crosses_module_system(installed_module_system, pv.module_system, project_declares_esm)
        ]
        newest = version_rules.newest_version(loadable)
        if newest is None or version_rules.compare_versions(newest.version, installed_version) < 0:
            return installed_version
        return newest.version
    except (ValueError, TypeError):
        # Mirrors compute_latest_compatible_major: unparseable release data means undeterminable.
        return None


def module_system_note(
    releases_since_installed: list[PackageVersion],
    installed_version: str,
    installed_module_system: ModuleSystem | None,
    version_rules: VersionRules,
    project_declares_esm: bool,
    *,
    now: datetime | None = None,
    node_version: str | None = None,
) -> str | None:
    """`esm_interop_note` when some newer installable release crosses to ESM-only, else None.

    One note per package rather than per version: it qualifies whichever ESM-only release a surface
    shows, whether that is the recommendation itself or the `latest_compatible_major` alternative.
    """
    try:
        newer = installable_releases(releases_since_installed, version_rules, now=now, newer_than=installed_version)
    except (ValueError, TypeError):
        return None
    if any(crosses_module_system(installed_module_system, pv.module_system, project_declares_esm) for pv in newer):
        return esm_interop_note(node_version)
    return None


def module_system_label(
    package_name: str,
    installed_version: str,
    target_version: str,
    releases: list[PackageVersion],
    registry: ProjectPackagesRegistry,
    project_declares_esm: bool,
) -> tuple[ModuleSystem | None, str | None]:
    """Return the target version's module system and a breaking-change note, if any.

    The note is None whenever the target loads from code on the installed module system — always
    the case for a `"type": "module"` project. It deliberately ignores the runtime: `require(esm)`
    returns the module namespace, so a default-export-only package (chalk) still breaks a CommonJS
    caller on every Node, and no manifest field says which shape a package has. The runtime
    qualifies the break (`esm_interop_note`); it never erases it.

    Args:
        package_name: Forwarded to `breaking_majors` for a target that was never published.
    """
    target_release = next((pv for pv in releases if pv.version == target_version), None)
    target_module_system = target_release.module_system if target_release else None
    installed_release = next((pv for pv in releases if pv.version == installed_version), None)
    installed_module_system = installed_release.module_system if installed_release else None

    if target_release is None:
        # An agent can ask about a version that was never published; its major's verdict is the
        # best evidence there is.
        if project_declares_esm or installed_module_system == ModuleSystem.ESM_ONLY:
            return None, None
        target_major = major_key(target_version, registry)
        flagged = breaking_majors(package_name, releases, registry) if target_major is not None else {}
        return None, flagged.get(target_major) if target_major is not None else None
    if not crosses_module_system(installed_module_system, target_module_system, project_declares_esm):
        return target_module_system, None
    return target_module_system, module_break_reason(target_release, releases, registry)
