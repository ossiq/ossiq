"""
ProjectSources: assembles external data providers for a scan run.
"""

from ossiq.adapters.api import (
    create_cve_database,
    create_package_registry_api,
    create_source_code_provider,
)
from ossiq.adapters.api_github import SourceCodeProviderApiGithub
from ossiq.adapters.package_managers.api import create_package_managers
from ossiq.adapters.package_managers.utils import normalize_dist_name
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider
from ossiq.domain.exceptions import UnknownProjectPackageManager
from ossiq.messages import WARNING_MULTIPLE_REGISTRY_TYPES
from ossiq.settings import Settings
from ossiq.sources.core import AbstractProjectSources
from ossiq.ui.system import show_warning


class ProjectSources(AbstractProjectSources):
    """
    Assembles and holds all external data providers needed for a single scan run.
    """

    def __init__(
        self,
        settings: Settings,
        project_path: str,
        narrow_package_registry: ProjectPackagesRegistry | None = None,
        production: bool = False,
        allow_prerelease: bool = False,
        allow_prerelease_packages: tuple[str, ...] = (),
        security_only: bool = False,
        ignore_packages: tuple[str, ...] = (),
        rewrite_versions: bool = False,
    ):
        """
        Store scan options; clients are initialized lazily in __enter__.
        """
        super().__init__()

        self.project_path = project_path
        self.settings = settings
        self.production = production
        self.allow_prerelease = allow_prerelease
        self.allow_prerelease_packages = allow_prerelease_packages
        self.security_only = security_only
        self.rewrite_versions = rewrite_versions
        self.ignore_packages = tuple(normalize_dist_name(p) for p in ignore_packages)
        self.narrow_package_registry = narrow_package_registry
        self.cve_database = create_cve_database(settings)

    def __enter__(self):
        """
        Initialize actual instances of respective clients (and other stuff when needed)
        """

        packages_managers = list(create_package_managers(self.project_path, self.settings))

        if not packages_managers:
            raise UnknownProjectPackageManager(f"Unable to identify Package Manager for project at {self.project_path}")

        if len(packages_managers) > 1 and not self.narrow_package_registry:
            show_warning(WARNING_MULTIPLE_REGISTRY_TYPES.format(project_path=self.project_path))

        packages_manager = packages_managers[0]

        if self.narrow_package_registry:
            packages_manager = next(
                (
                    manager
                    for manager in packages_managers
                    if manager.package_manager_type.package_registry == self.narrow_package_registry
                ),
                None,
            )
            if not packages_manager:
                detected = ", ".join(m.package_manager_type.name for m in packages_managers)
                raise UnknownProjectPackageManager(
                    f"Unable to narrow Package Manager to {self.narrow_package_registry} "
                    f"for project at {self.project_path}",
                    hint=f"Detected: {detected}. Use --registry-type to match what was found, or omit it.",
                )

        self.packages_manager = packages_manager
        self.packages_registry = create_package_registry_api(
            packages_manager.package_manager_type.package_registry, self.settings
        )

    def __exit__(self, *args):
        pass

    def get_source_code_provider(self, repository_provider_type: RepositoryProvider) -> SourceCodeProviderApiGithub:
        """
        Return source code provider (like Github) using factory and respective type
        """
        return create_source_code_provider(repository_provider_type, self.settings)


REGISTRY_TYPE_MAP: dict[str, ProjectPackagesRegistry] = {
    "npm": ProjectPackagesRegistry.NPM,
    "pypi": ProjectPackagesRegistry.PYPI,
}


def build_project_sources(
    settings: Settings,
    project_path: str,
    production: bool,
    allow_prerelease: bool,
    allow_prerelease_packages: tuple[str, ...],
    registry_type: str | None,
    *,
    security_only: bool = False,
    ignore_packages: tuple[str, ...] = (),
    rewrite_versions: bool = False,
) -> ProjectSources:
    """Factory for ProjectSources with registry-type string mapping applied."""
    return ProjectSources(
        settings=settings,
        project_path=project_path,
        production=production,
        allow_prerelease=allow_prerelease,
        allow_prerelease_packages=allow_prerelease_packages,
        narrow_package_registry=REGISTRY_TYPE_MAP.get(registry_type or ""),
        security_only=security_only,
        ignore_packages=ignore_packages,
        rewrite_versions=rewrite_versions,
    )
