"""
Module to operate with NPM registry
"""
import json
import os
import requests

from .package import Package, REGISTRY_NPM
from .project import Project, PROJECT_TYPE_NPM

NPM_REGISTRY = "https://registry.npmjs.org"
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


def find_installed_version(pkg_json: dict, package: str) -> str | None:
    """
    Find installed version of a package in package.json.
    Returns None if not found.
    """
    for field in NPM_DEPENDENCIES_SECTIONS:
        if package in (pkg_json.get(field) or {}):
            return pkg_json[field][package]
    return None


def fetch_npm_info(package_name: str) -> Package:
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
        repo=response.get("repository"),
        author=response.get("author"),
        url=response.get("homepage"),
        description=response.get("description")
    )


def extract_github_repo_url(npm_info: dict) -> str | None:
    rep = npm_info.get("repository")
    if isinstance(rep, dict):
        return rep.get("url")
    return rep
