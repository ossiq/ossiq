"""
ProjectSources: assembles external data providers for a scan run.
"""

from pathlib import Path

from ossiq.adapters.api import (
    create_cve_database,
    create_epss_score_database,
    create_package_registry_api,
    create_source_code_provider,
)
from ossiq.adapters.api_interfaces import AbstractSourceCodeProviderApi
from ossiq.adapters.package_managers.api import create_package_managers, inspected_manifests
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider, normalize_dist_name
from ossiq.domain.exceptions import UnknownProjectPackageManager
from ossiq.messages import HINT_NO_PACKAGE_MANAGER, WARNING_MULTIPLE_REGISTRY_TYPES
from ossiq.settings import Settings
from ossiq.sources.core import AbstractProjectSources
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import DEFAULT_STRATEGY, PRERELEASE_TIERS


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
        strategy: StrategyPlan | None = None,
        ignore_packages: tuple[str, ...] = (),
        rewrite_versions: bool = False,
    ):
        """
        Store scan options; clients are initialized lazily in __enter__.
        """
        super().__init__()

        # Diagnostics, not output: __enter__ collects here and the scan carries them onto
        # ScanResult, so the renderer decides how (and whether) a surface shows them. This module
        # used to call ui.system.show_warning directly, which printed to stderr even for the
        # JSON-emitting front doors that have their own channel for it.
        self.warnings: list[str] = []
        self.project_path = project_path
        self.settings = settings
        self.production = production
        self.strategy = strategy or StrategyPlan(default=DEFAULT_STRATEGY)
        # cutting-edge admits prereleases; handled at prefetch, not as a sixth ladder rung — see
        # strategy/README.md. A per-package override to cutting-edge only widens that package.
        self.allow_prerelease = allow_prerelease or self.strategy.default in PRERELEASE_TIERS
        self.allow_prerelease_packages = tuple(set(allow_prerelease_packages) | set(self.strategy.prerelease_packages))
        self.rewrite_versions = rewrite_versions
        self.ignore_packages = tuple(normalize_dist_name(p) for p in ignore_packages)
        self.narrow_package_registry = narrow_package_registry
        self.cve_database = create_cve_database(settings)
        self.epss_score_database = create_epss_score_database(settings)

    def __enter__(self):
        """
        Initialize actual instances of respective clients (and other stuff when needed)
        """

        packages_managers = list(create_package_managers(self.project_path, self.settings))

        if not packages_managers:
            manifest_names = inspected_manifests()
            found = [name for name in manifest_names if (Path(self.project_path) / name).exists()]
            raise UnknownProjectPackageManager(
                f"Unable to identify Package Manager for project at {self.project_path}",
                hint=HINT_NO_PACKAGE_MANAGER.format(
                    inspected=", ".join(manifest_names),
                    found=", ".join(found) if found else "none",
                ),
            )

        # create_package_managers yields at most one adapter per registry, so more than one here is
        # genuinely more than one ecosystem - not two adapters arguing over the same pyproject.toml.
        if len(packages_managers) > 1 and not self.narrow_package_registry:
            self.warnings.append(WARNING_MULTIPLE_REGISTRY_TYPES.format(project_path=self.project_path).strip())

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

    def get_source_code_provider(self, repository_provider_type: RepositoryProvider) -> AbstractSourceCodeProviderApi:
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
    strategy: StrategyPlan | None = None,
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
        strategy=strategy,
        ignore_packages=ignore_packages,
        rewrite_versions=rewrite_versions,
    )
