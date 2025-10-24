"""
Implementation of Package Registry API client for NPM
"""

from typing import Iterable
import requests
from rich.console import Console

from update_burden.adapters.api_interfaces import AbstractPackageRegistryApiClient
from update_burden.domain.common import PackageRegistryType
from update_burden.domain.package import Package
from update_burden.domain.version import PackageVersion

console = Console()

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_REGISTRY_FRONT = "https://www.npmjs.com"

NPM_DEPENDENCIES_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies"
    # FIXME: consider pinned versions as well!
)


class NpmRegistryApiClient(AbstractPackageRegistryApiClient):
    """
    Implementation of Package Registry API client for NPM
    """

    def __init__(self):
        pass

    def _make_request(self, path: str, timeout: int = 15) -> dict:
        """
        Make request and handle retries and errors handling.
        """
        r = requests.get(f"{NPM_REGISTRY}{path}", timeout=timeout)
        r.raise_for_status()
        return r.json()

    def package_info(self, package_name: str) -> dict:
        """
        Fetch npm info for a given package.
        FIXME: raise custom exception if not found
        """
        response = self._make_request(f"/{package_name}")
        distribution_tags = response.get(
            "dist-tags", {"latest": None, "next": None})

        return Package(
            registry=PackageRegistryType.REGISTRY_NPM,
            name=response["name"],
            latest_version=distribution_tags.get("latest", None),
            next_version=distribution_tags.get("next", None),
            repo_url=response.get("repository", {}).get("url", None),
            author=response.get("author"),
            homepage_url=response.get("homepage"),
            description=response.get("description"),
            package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/"
        )

    def package_versions(self, package_name: str) -> Iterable[PackageVersion]:
        """
        Fetch npm versions for a given package.
        """
        response = self._make_request(f"/{package_name}")
        # FIXME: raise custom exception if not found
        versions = response.get("versions", [])

        for version, details in versions.items():
            yield PackageVersion(
                version=version,
                dependencies=details.get("dependencies", {}),
                license=details.get("license", None),
                runtime_requirements=details.get("engines", None),
                dev_dependencies=details.get("devDependencies", {}),
                description=details.get("description", None),
                package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/v/{version}"
            )
