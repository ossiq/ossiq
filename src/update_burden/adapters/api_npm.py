"""
Implementation of Package Registry API client for NPM
"""

import json
import os

from typing import Iterable

import requests
from rich.console import Console

from update_burden.adapters.api_interfaces import AbstractPackageRegistryApi
from update_burden.domain.common import ProjectPackagesRegistryKind
from update_burden.domain.package import Package
from update_burden.domain.project import Project
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


class PackageRegistryApiNpm(AbstractPackageRegistryApi):
    """
    Implementation of Package Registry API client for NPM
    """

    def __repr__(self):
        return "<PackageRegistryApiNpm instance>"

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
            registry=ProjectPackagesRegistryKind.NPM,
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

    def project_info(self, project_path: str) -> Project:
        """
        Method to return a particular Project info
        with all installed dependencies with their versions
        """
        project_file_path = os.path.join(project_path, "package.json")
        if not os.path.exists(project_file_path):
            raise FileNotFoundError(
                f"package.json not found at `{project_file_path}`")

        with open(project_file_path, "r", encoding="utf-8") as f:
            project_json = json.load(f)
            fallback_name = os.path.basename(project_path)

            return Project(
                package_registry=ProjectPackagesRegistryKind.NPM,
                name=project_json.get("name", fallback_name),
                project_path=project_path,
                project_files=[project_file_path],
                dependencies=project_json.get("dependencies", {}),
                # TODO: for simplicity merge these, but probably
                # just needs to introduce priority for dependencies to calculate risk score later
                # FIXME: take care of the pinned dependencies later
                dev_dependencies={
                    **project_json.get("devDependencies", {}),
                    **project_json.get("peerDependencies", {}),
                    **project_json.get("optionalDependencies", {}),
                }
            )
