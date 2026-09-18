"""
Go over all available package managers APIs and
figure out which is appropriate for the project.

Note, that there could be multiple for mixed projects.
"""

from collections.abc import Iterable

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.adapters.package_managers.api_pep621 import PackageManagerPythonPep621
from ossiq.adapters.package_managers.api_pip import PackageManagerPythonPip
from ossiq.adapters.package_managers.api_pip_classic import PackageManagerPythonPipClassic
from ossiq.adapters.package_managers.api_uv import PackageManagerPythonUv
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.settings import Settings

# Precedence order, highest-featured adapter per registry first: create_package_managers yields at
# most one adapter per registry and this tuple is what decides which. A lockfile-backed adapter must
# come before a manifest-only one for the same registry (uv/pylock before pep621, pep621 before
# pip-classic), so a project with a real lockfile gets the fuller-featured driver.
PACKAGE_MANAGERS = (
    PackageManagerPythonUv,
    PackageManagerPythonPip,
    PackageManagerPythonPep621,
    PackageManagerPythonPipClassic,
    PackageManagerJsNpm,
)


def create_package_managers(project_path: str, settings: Settings) -> Iterable[AbstractPackageManagerApi]:
    """Detect the package managers used in a project directory, at most one per registry.

    Adapters for the same registry regularly match the same tree - a uv project also has a
    `pyproject.toml` a PEP 621 adapter recognises, and may have a `requirements.txt` too. Yielding
    every match made those ties the adapters' own problem to break (api_pep621 used to call its two
    siblings' `has_package_manager` directly) and made `ProjectSources` warn about "multiple
    registry types" when both matches were the same registry. Precedence is the registry's job:
    first match per registry wins, in PACKAGE_MANAGERS order.

    Args:
        project_path: The project directory to probe.
        settings: Run settings, handed to each adapter constructed.

    Returns:
        One adapter instance per registry found, so more than one result means genuinely more than
        one ecosystem in the tree.
    """
    claimed: set[ProjectPackagesRegistry] = set()
    for managerType in PACKAGE_MANAGERS:
        registry = managerType.package_manager_type.package_registry
        if registry in claimed:
            continue
        if managerType.has_package_manager(project_path):
            claimed.add(registry)
            yield managerType(project_path, settings)


def inspected_manifests() -> tuple[str, ...]:
    """The manifest filenames the registered adapters look for, in precedence order.

    So `UnknownProjectPackageManager`'s hint can name what was actually inspected instead of
    `sources/` keeping its own hardcoded copy of adapter knowledge - which would go stale the
    moment an adapter is added.
    """
    return tuple(dict.fromkeys(m.package_manager_type.primary_manifest.name for m in PACKAGE_MANAGERS))
