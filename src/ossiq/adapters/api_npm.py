"""
Implementation of Package Registry API client for NPM
"""

from collections.abc import Iterable

import requests
from rich.console import Console

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package
from ossiq.domain.version import PackageVersion
from ossiq.settings import Settings

console = Console()

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_REGISTRY_FRONT = "https://www.npmjs.com"

NPM_DEPENDENCIES_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    # FIXME: consider pinned versions as well!
)


class PackageRegistryApiNpm(AbstractPackageRegistryApi):
    """
    Implementation of Package Registry API client for NPM
    """

    package_registry = ProjectPackagesRegistry.NPM
    settings: Settings

    def __init__(self, settings: Settings):
        self.settings = settings

    def __repr__(self):
        return "<PackageRegistryApiNpm instance>"

    def _make_request(self, path: str, headers: dict | None = None, timeout: int = 15) -> dict:
        """
        Make request and handle retries and errors handling.
        """
        r = requests.get(f"{NPM_REGISTRY}{path}", timeout=timeout, headers=headers)
        r.raise_for_status()
        return r.json()

    def package_info(self, package_name: str) -> Package:
        """
        Fetch npm info for a given package.
        FIXME: raise custom exception if not found
        """
        response = self._make_request(f"/{package_name}")
        distribution_tags = response.get("dist-tags", {"latest": None, "next": None})

        return Package(
            registry=ProjectPackagesRegistry.NPM,
            name=response["name"],
            latest_version=distribution_tags.get("latest", None),
            next_version=distribution_tags.get("next", None),
            repo_url=response.get("repository", {}).get("url", None),
            author=response.get("author"),
            homepage_url=response.get("homepage"),
            description=response.get("description"),
            package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/",
        )

    def package_versions(self, package_name: str) -> Iterable[PackageVersion]:
        """
        Fetch npm versions for a given package.
        """
        response = self._make_request(f"/{package_name}")
        # FIXME: raise custom exception if not found
        versions = response.get("versions", [])
        timestamp_map = response.get("time", {})
        unpublished_response = timestamp_map.pop("unpublished", {})

        # Package version is either published or unpublished
        if unpublished_response:
            unpublished_date_iso = unpublished_response.get("time", None)
            for version in unpublished_response.get("versions", []):
                yield PackageVersion(
                    version=version,
                    license=None,
                    dependencies={},
                    package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/v/{version}",
                    unpublished_date_iso=unpublished_date_iso,
                    is_published=False,
                )
        else:
            for version, details in versions.items():
                yield PackageVersion(
                    version=version,
                    published_date_iso=timestamp_map.get(version, None),
                    dependencies=details.get("dependencies", {}),
                    license=details.get("license", None),
                    runtime_requirements=details.get("engines", None),
                    dev_dependencies=details.get("devDependencies", {}),
                    description=details.get("description", None),
                    package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/v/{version}",
                )
