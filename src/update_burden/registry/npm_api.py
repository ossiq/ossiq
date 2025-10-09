"""
Module to operate with NPM registry
"""
import json
import os
from typing import List
import requests

from .common import REGISTRY_NPM, PROJECT_TYPE_NPM
from .package import Package
from .project import Project
from .versions import PackageVersion, normalize_version

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_REGISTRY_FRONT = "https://www.npmjs.com"
NPM_DEPENDENCIES_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies"
)


def parse_npm_project_info(path: str) -> dict:
    """
    Read package.json from a given path.
    Raises FileNotFoundError if not found.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"package.json not found at {path}")
    with open(path, "r", encoding="utf-8") as f:
        project_json = json.load(f)
        return Project(
            project_type=PROJECT_TYPE_NPM,
            name=project_json["name"],
            dependencies=project_json.get("dependencies", {}),
            # TODO: for simplicity merge these, but probably
            # just needs to introduce priority for dependencies to calculate risk score later
            dev_dependencies={
                **project_json.get("devDependencies", {}),
                **project_json.get("peerDependencies", {}),
                **project_json.get("optionalDependencies", {}),
            }
        )


def load_npm_package(package_name: str) -> Package:
    """
    Fetch npm info for a given package.
    Raises HTTPError if not found.
    """
    r = requests.get(f"{NPM_REGISTRY}/{package_name}", timeout=15)
    r.raise_for_status()
    response = r.json()
    distribution_tags = response.get(
        "dist-tags", {"latest": None, "next": None})

    return Package(
        registry=REGISTRY_NPM,
        name=response["name"],
        version=distribution_tags.get("latest", None),
        next_version=distribution_tags.get("next", None),
        repo_url=response.get("repository", {}).get("url", None),
        author=response.get("author"),
        homepage_url=response.get("homepage"),
        description=response.get("description")
    )


def load_npm_package_versions(package_name: str) -> List[PackageVersion]:
    """
    Fetch npm versions for a given package.
    Raises HTTPError if not found.
    """
    r = requests.get(f"{NPM_REGISTRY}/{package_name}", timeout=15)
    r.raise_for_status()
    versions = r.json().get("versions", [])

    # Much simpler API down the road
    result_versions = []
    for version, details in versions.items():
        result_versions.append(
            PackageVersion(
                version=version,
                normalized_version=normalize_version(version),
                dependencies=details.get("dependencies", {}),
                license=details.get("license", None),
                package_version_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/v/{version}",
                engine_versions=details.get("engines", {}),
                dev_dependencies=details.get("devDependencies", {}),
                description=details.get("description", None)
            ))
    return result_versions
