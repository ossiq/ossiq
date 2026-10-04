"""Which of a PyPI release's declared requirements apply to a project (PEP 508 extras and markers).

Pure: no I/O. The registry adapters and the solver both read requirements through here, so an extra
or an environment marker is judged in exactly one place.
"""

from collections.abc import Iterable
from functools import cache, lru_cache

from packaging.markers import Marker, UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

# Without a project floor every minor back to here counts as reachable, which keeps a marker such as
# `python_version < "3.11"` alive instead of silently dropping it.
OLDEST_PYTHON_MINOR = 8
# Upper edge of the grid; a marker like `python_version >= "3.15"` has to stay reachable, so this
# trails the newest CPython that PyPI already ships wheels for.
NEWEST_PYTHON_MINOR = 15
# A marker on `python_full_version` can split a minor in two; patch 0 and a high patch see both halves.
PATCH_SAMPLES = (0, 99)

PLATFORMS = (
    {"sys_platform": "linux", "os_name": "posix", "platform_system": "Linux"},
    {"sys_platform": "darwin", "os_name": "posix", "platform_system": "Darwin"},
    {"sys_platform": "win32", "os_name": "nt", "platform_system": "Windows"},
)
# Windows reports ARM64 and AMD64 where Linux and macOS report aarch64/arm64 and x86_64.
MACHINES = ("x86_64", "AMD64", "arm64", "aarch64", "ARM64")
IMPLEMENTATIONS = (("cpython", "CPython"), ("pypy", "PyPy"))


def python_floor_minor(python_floor: str | None) -> tuple[int, int]:
    """Parse a floor such as "3.12" into (major, minor), falling back to the oldest supported minor."""
    fallback = (3, OLDEST_PYTHON_MINOR)
    if not python_floor:
        return fallback
    try:
        release = Version(python_floor).release
    except InvalidVersion:
        return fallback
    if len(release) < 2 or release[0] != 3:
        return fallback
    return (release[0], release[1])


@cache
def environments(floor: tuple[int, int]) -> tuple[dict[str, str], ...]:
    """Enumerate the environments a project with the given Python floor can be installed into.

    Every value a marker may read is fixed, so the answer does not depend on the machine running
    the scan.
    """
    major, oldest = floor
    envs: list[dict[str, str]] = []
    for minor in range(oldest, max(NEWEST_PYTHON_MINOR, oldest) + 1):
        for patch in PATCH_SAMPLES:
            for platform in PLATFORMS:
                for machine in MACHINES:
                    for implementation_name, implementation in IMPLEMENTATIONS:
                        full_version = f"{major}.{minor}.{patch}"
                        envs.append(
                            {
                                **platform,
                                "python_version": f"{major}.{minor}",
                                "python_full_version": full_version,
                                "implementation_name": implementation_name,
                                "implementation_version": full_version,
                                "platform_python_implementation": implementation,
                                "platform_machine": machine,
                                "platform_release": "",
                                "platform_version": "",
                            }
                        )
    return tuple(envs)


@lru_cache(maxsize=8192)
def marker_reachable(marker: str, extras: frozenset[str], floor: tuple[int, int]) -> bool:
    """Return True when *marker* holds in at least one environment the project can be installed into.

    A requirement is dropped only when no supported environment reaches it, which is the same
    stance uv's universal resolution takes. An unknown marker variable counts as reachable: we
    cannot prove the requirement is irrelevant.

    Args:
        marker: The marker text, e.g. `python_version < "3.11" and extra == "dev"`.
        extras: Canonical names of the extras the project enables.
        floor: (major, minor) of the oldest Python the project supports.
    """
    parsed = Marker(marker)
    for extra in (*sorted(extras), ""):
        for env in environments(floor):
            try:
                if parsed.evaluate({**env, "extra": extra}):
                    return True
            except (UndefinedComparison, UndefinedEnvironmentName):
                return True
    return False


def applicable_requirements(
    requires_dist: Iterable[str],
    extras: Iterable[str] = (),
    python_floor: str | None = None,
) -> dict[str, str]:
    """Parse `requires_dist` lines into {canonical_name: specifier}, keeping only those that apply.

    A name that survives more than once (several extras, several markers) gets the intersection
    of its specifiers, so no constraint is lost to whichever line came last. An unconstrained
    requirement maps to "". Lines that do not parse are skipped.

    Args:
        requires_dist: PEP 508 requirement strings as published in a release's metadata.
        extras: Extras enabled on the package that declares them.
        python_floor: Oldest Python the project supports as "X.Y"; None means no floor.

    Returns:
        Mapping of canonical (PEP 503) name to specifier string.
    """
    enabled = frozenset(canonicalize_name(extra) for extra in extras)
    floor = python_floor_minor(python_floor)
    merged: dict[str, SpecifierSet] = {}
    for line in requires_dist:
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue
        if requirement.marker is not None and not marker_reachable(str(requirement.marker), enabled, floor):
            continue
        name = canonicalize_name(requirement.name)
        merged[name] = merged[name] & requirement.specifier if name in merged else requirement.specifier
    return {name: str(specifier) for name, specifier in merged.items()}
