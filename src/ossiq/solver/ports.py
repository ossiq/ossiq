"""What pure resolution needs from a package registry, declared here so `adapters/` implements it.

The solver and the strategy code only read registry data; the HTTP side lives in
`adapters.api_interfaces.AbstractPackageRegistryApi`, which extends `RegistryReader`.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable
from functools import cmp_to_key

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.requirement_scope import RequirementScope
from ossiq.domain.version import PackageVersion, PeerDependency, VersionsDifference


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


class RegistryReader(VersionRules, abc.ABC):
    """The registry data the solver and the update strategy read: versions, requirements, peers."""

    # Shared default is safe: RequirementScope is frozen, and use_requirement_scope rebinds the attribute.
    requirement_scope: RequirementScope = RequirementScope()

    # pip and uv install one version of a package per environment, so every dependent's range has to
    # hold for it at once. npm instead nests a further copy when a dependent's range cannot share the
    # one already installed; only a peer or an `overrides` rule forces a single instance there.
    one_copy_per_name: bool = True
    # pip and uv refuse a version whose engine requirement the runtime cannot meet. npm installs it
    # with a warning, so there a mismatch stays advisory.
    refuses_engine_mismatch: bool = True

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

    def package_version_peers(self, package_name: str, version: str) -> dict[str, PeerDependency]:
        """Return {dep_name: PeerDependency} for a specific published version.

        Only npm declares peers, so the default is none; an empty result is "no peer constraints",
        not "unknown".
        """
        return {}
