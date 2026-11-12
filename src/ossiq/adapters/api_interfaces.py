"""
Interfaces related to external APIs
"""

from __future__ import annotations

import abc
from collections.abc import Callable, Iterable

from ossiq.domain.common import RateLimitBudget, SourceFetch
from ossiq.domain.exceptions import PackageManagerOperationUnsupported
from ossiq.domain.package import Package
from ossiq.domain.packages_manager import PackageManagerType
from ossiq.domain.project import Project
from ossiq.domain.provenance import SourceLevel
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.domain.requirement_scope import RequirementScope
from ossiq.domain.update_plan import UpdatePlan
from ossiq.settings import Settings
from ossiq.solver.ports import RegistryReader

from ..domain.repository import Repository
from ..domain.version import PackageVersion, RepositoryVersion


class AbstractSourceCodeProviderApi(abc.ABC):
    """
    Abstract client to communicate with source code repositories like GitHub

    Every batch method returns its payload wrapped in a `SourceFetch`, so a caller can tell
    "checked, found nothing" apart from "couldn't check at all" without interrogating the
    instance afterwards. The port deliberately speaks `DataSourceStatus`, not the `clients/`
    batch-run type it happens to be derived from.
    """

    @abc.abstractmethod
    def repository_info(self, repository_url: str | None) -> Repository:
        raise NotImplementedError

    @abc.abstractmethod
    def repositories_info_batch(self, repo_urls: list[str]) -> SourceFetch[dict[str, Repository]]:
        """Fetch metadata for multiple repos in parallel. Returns url -> Repository."""
        raise NotImplementedError

    @abc.abstractmethod
    def repository_versions(
        self, repository: Repository, package_versions: list[PackageVersion], comparator: Callable
    ) -> Iterable[RepositoryVersion]:
        raise NotImplementedError

    @abc.abstractmethod
    def commits_batch(self, repo_urls: list[str], until: str | None = None) -> SourceFetch[dict[str, list[dict]]]:
        """Fetch recent commits for multiple repos in parallel. Feeds the stability estimator."""
        raise NotImplementedError

    @abc.abstractmethod
    def repository_activity_batch(self, repo_urls: list[str], since: str | None = None) -> SourceFetch[dict[str, dict]]:
        """Fetch issue / PR activity for multiple repos in parallel."""
        raise NotImplementedError

    @abc.abstractmethod
    def readmes_batch(self, repo_urls: list[str]) -> SourceFetch[dict[str, str]]:
        """Fetch the top of each repo's README in parallel, for the deprecation-banner scan."""
        raise NotImplementedError

    def branch_controls_batch(self, branches: dict[str, str]) -> SourceFetch[dict[str, SourceLevel]]:
        """Read how each repository protects its default branch.

        Not abstract: a provider that cannot say simply reports nothing, which every surface shows as
        "unknown" rather than "unprotected".

        Args:
            branches: Repository URL -> the name of its default branch.

        Returns:
            Source level per repository; a repository that could not be read is absent.
        """
        return SourceFetch({})

    @abc.abstractmethod
    def rate_limit_budgets(self) -> tuple[RateLimitBudget, ...]:
        """Report the provider's remaining quota, without spending any of it."""
        raise NotImplementedError

    @abc.abstractmethod
    def __repr__(self):
        raise NotImplementedError


class AbstractPackageRegistryApi(RegistryReader, abc.ABC):
    """I/O client for fetching package data from a registry (PyPI, NPM, etc.)."""

    settings: Settings

    def use_requirement_scope(self, scope: RequirementScope) -> None:
        """Read declared requirements under *scope* from now on.

        PyPI gates requirements on extras and environment markers, so which ones apply depends on
        the project asking. Registries with no such gating (npm) ignore it.
        """
        self.requirement_scope = scope

    @abc.abstractmethod
    def packages_info_batch(self, names: list[str]) -> dict[str, Package]:
        """Fetch info for a list of packages, returning a mapping of name -> Package."""
        raise NotImplementedError

    def package_info(self, package_name: str) -> Package:
        """Get a particular package info. Delegates to package_infos_batch by default."""
        return self.packages_info_batch([package_name])[package_name]

    @abc.abstractmethod
    def __repr__(self):
        raise NotImplementedError

    def fetch_downloads_recent(self, package_name: str) -> int | None:
        """Fetch last-month download count for a package. Returns None if unavailable."""
        return None


class AbstractPackageManagerApi(abc.ABC):
    """
    Abstract Package Manager to extract installed versions
    of packages from different package managers.
    """

    settings: Settings
    package_manager_type: PackageManagerType
    project_path: str
    # True when `execute_update` and `install_package` hold packages entering the tree to the cooldown
    # period themselves, so the plan need not warn that such packages sit outside it.
    enforces_cooldown_on_install: bool = False
    # True when `execute_update` exempts an `--override` version from the package manager's own
    # release cutoff, so the forced version installs even though the cutoff refuses it.
    exempts_forced_versions: bool = False
    # True when `ossiq upgrade` can roll a step back: `execute_update` writes only snapshot_files().
    supports_upgrade_session: bool = False

    @staticmethod
    @abc.abstractmethod
    def has_package_manager(project_path: str) -> bool:
        """
        Detect that package manager is used in a project_path
        """
        pass

    @abc.abstractmethod
    def project_info(self) -> Project:
        """
        Extract project dependencies using file format from a specific
        package manager.
        """
        pass

    def release_cutoff(self) -> ReleaseCutoff | None:
        """Return the newest publish instant this package manager will resolve to, if it has one.

        A release past it is one `apply` cannot install whatever OSS IQ recommends, so the
        registry drops it before anything picks a target. Defaults to None (no cutoff).
        """
        return None

    def installer_caps(self) -> dict[str, str]:
        """Return the ranges this package manager applies to every resolution, by normalised package name.

        uv's `[tool.uv] constraint-dependencies`, pip's `-c` files: nothing outside one can be installed,
        so nothing outside one may be recommended. Defaults to no caps.
        """
        return {}

    def execute_update(self, plan: UpdatePlan, on_pass: Callable[[int, int], None] | None = None) -> None:
        """Execute the update plan in-process.

        Supported package managers override this. Default raises PackageManagerOperationUnsupported.

        Args:
            plan: The plan to apply.
            on_pass: Called as `(number, total)` before each install pass of a multi-pass plan, so the
                caller can say where it is. A package manager that installs in one go never calls it.
        """
        raise PackageManagerOperationUnsupported(
            f"In-process execution is not yet supported for {self.package_manager_type.name}."
        )

    def snapshot_files(self) -> tuple[str, ...]:
        """Names, relative to the project, of the files `execute_update` may rewrite; `upgrade` snapshots them."""
        pm = self.package_manager_type
        return (pm.primary_manifest.name, *([pm.lockfile.name] if pm.lockfile else []))

    def sync_environment(self) -> None:
        """Make the installed packages match the manifest and lockfile on disk, e.g. after a rollback.

        Raises:
            PackageManagerExecutionError: The package manager failed or is not installed.
        """
        raise PackageManagerOperationUnsupported(
            f"Syncing the environment is not yet supported for {self.package_manager_type.name}."
        )

    def install_package(self, package_name: str, version: str | None = None) -> int:
        """Install a package into the project. Returns subprocess exit code on success.

        Supported package managers override this. Adapters with a manifest to protect (uv, npm, pnpm)
        raise PackageManagerExecutionError and restore the original manifest on subprocess
        failure, rather than returning a nonzero code.
        """
        raise PackageManagerOperationUnsupported(
            f"Package installation is not yet supported for {self.package_manager_type.name}."
        )
