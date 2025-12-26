"""
Go over all available package managers APIs and
figure out which is appropriate for the project.

Note, that there could be multiple for mixed projects.
"""

from collections.abc import Iterable

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.api_uv import PackageManagerPythonUv
from ossiq.settings import Settings

PACKAGE_MANAGERS = (PackageManagerPythonUv,)


def create_package_managers(project_path: str, settings: Settings) -> Iterable[AbstractPackageManagerApi]:
    """
    Detects the package manager used in a project directory by probing for
    lockfiles first, then manifest files.
    """
    for managerType in PACKAGE_MANAGERS:
        if managerType.has_package_manager(project_path):
            yield managerType(project_path, settings)
