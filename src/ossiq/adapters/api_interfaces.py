"""
Interfaces related to external APIs
"""

from __future__ import annotations

import abc
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cmp_to_key
from typing import TYPE_CHECKING

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.package import Package
from ossiq.domain.packages_manager import PackageManagerType
from ossiq.domain.project import Project
from ossiq.settings import Settings

from ..domain.version import PackageVersion, VersionsDifference

if TYPE_CHECKING:
    from ossiq.service.update import UpdatePlan


class VersionRules(abc.ABC):
    """Pure version semantics: registry-specific comparison and specifier rules, no I/O."""

    package_registry: ProjectPackagesRegistry

    @staticmethod
    @abc.abstractmethod
    def compare_versions(v1: str, v2: str) -> int:
        """
        Compare two versions regardless of the registry.

        Versioning is registry-specific, for example
        JavaScript/NPM follows Semantic Versioning strictly,
        while Python/PyPI ecosystem follows PEP 440.
        """
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def difference_versions(v1_str: str | None, v2_str: str | None) -> VersionsDifference:
        """
        Calculate version difference using registry-specific semantics.

        Categorizes the difference between two versions (major, minor, patch, etc.)
        based on the versioning scheme used by the registry.

        Args:
            v1: First version string (e.g., installed version)
            v2: Second version string (e.g., latest version)

        Returns:
            VersionsDifference object with categorized diff index
        """
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def rewrite_specifier(
        specifier: str | None,
        new_version: str,
        constraint_type: ConstraintType | None = None,
    ) -> str | None:
        """Rewrite a version specifier for an updated package version."""
        raise NotImplementedError

    def newest_version(self, candidates: Iterable[PackageVersion]) -> PackageVersion | None:
        """Return the newest PackageVersion from candidates using registry-specific comparison.

        Returns None when candidates is empty.
        """
        as_list = list(candidates)
        if not as_list:
            return None
        return max(as_list, key=cmp_to_key(lambda a, b: self.compare_versions(a.version, b.version)))


class AbstractPackageRegistryApi(VersionRules, abc.ABC):
    """I/O client for fetching package data from a registry (PyPI, NPM, etc.)."""

    settings: Settings

    @abc.abstractmethod
    def packages_info_batch(self, names: list[str]) -> dict[str, Package]:
        """Fetch info for a list of packages, returning a mapping of name -> Package."""
        raise NotImplementedError

    def package_info(self, package_name: str) -> Package:
        """Get a particular package info. Delegates to package_infos_batch by default."""
        return self.packages_info_batch([package_name])[package_name]

    @abc.abstractmethod
    def package_versions(self, package_name: str) -> Iterable[PackageVersion]:
        """
        Get a particular package versions between what is installed
        currently in the project and the latest version available
        """
        raise NotImplementedError

    @abc.abstractmethod
    def package_version_requires(self, package_name: str, version: str) -> dict[str, str]:
        """Return {normalized_dep_name: version_specifier} for a specific published version.

        Returns empty dict if the version is not found or has no runtime dependencies.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def __repr__(self):
        raise NotImplementedError

    def fetch_downloads_recent(self, package_name: str) -> int | None:
        """Fetch last-month download count for a package. Returns None if unavailable."""
        return None


@dataclass(frozen=True)
class HelperSpec:
    """Metadata for a package manager helper sub-command."""

    name: str
    description: str


class AbstractPackageManagerApi(abc.ABC):
    """
    Abstract Package Manager to extract installed versions
    of packages from different package managers.
    """

    settings: Settings
    package_manager_type: PackageManagerType
    project_path: str

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

    @classmethod
    def helper_specs(cls) -> list[HelperSpec]:
        """Return metadata for available helper sub-commands. Override per package manager."""
        return []

    def generate_update_script(self, plan: UpdatePlan, cli_extra_args: str = "") -> str:
        """Generate a bash update script for the recommended versions in plan.

        Default returns an unsupported notice with the version list as comments.
        Supported package managers override this with an atomic update script.
        cli_extra_args is forwarded to sub-command invocations in the script (NPM only).
        """
        lines = [
            f"# OSS IQ update — {self.package_manager_type.name}  |  project: {plan.project_name}",
            f"# Automated update scripts are not yet supported for {self.package_manager_type.name}.",
            "# Apply the following recommended versions manually:",
            "#",
        ]
        for entry in plan.all_entries:
            lines.append(f"#   {entry.package_name}: {entry.current_version} -> {entry.recommended_version}")
        return "\n".join(lines)

    def execute_update(self, plan: UpdatePlan) -> None:
        """Execute the update plan in-process.

        Supported package managers override this. Default raises NotImplementedError.
        """
        raise NotImplementedError(
            f"In-process execution is not yet supported for {self.package_manager_type.name}. "
            "Use 'ossiq update plan --script' to generate a bash script instead."
        )

    def install_package(self, package_name: str, version: str | None = None) -> int:
        """Install a package into the project. Returns subprocess exit code.

        Supported package managers override this.
        """
        raise NotImplementedError(f"Package installation is not yet supported for {self.package_manager_type.name}.")
