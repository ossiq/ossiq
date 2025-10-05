"""
Aggregate all the changes around a package both
local and remote.
"""
import pprint

from typing import List

from .common import REGISTRY_NPM, REPOSITORY_PROVIDER_GITHUB
from .package import Package
from .project import Project
from .repository import Repository
from .versions import PackageVersion, RepositoryVersion, Version
from .npm_api import (
    load_npm_package,
    parse_npm_project_info,
    load_npm_package_versions
)
from .gh_api import (
    load_github_repository,
    load_github_code_versions
)
# from .versions import normalize_version


def extract_project_info(registry_type: str, path: str) -> Project:
    """
    Extract project info from a given path.
    """
    if registry_type == REGISTRY_NPM:
        return parse_npm_project_info(path)

    raise ValueError(f"Unknown registry type: {registry_type}")


def extract_package_info(registry_type: str, package_name: str) -> Package:
    """
    Extract package info from a given project.
    """
    if registry_type == REGISTRY_NPM:
        return load_npm_package(package_name)

    raise ValueError(f"Unknown registry type: {registry_type}")


def load_package_versions(package: Package, repository: Repository) -> List[Version]:
    """
    Load package versions from a given registry.
    """
    package_versions: List[PackageVersion] | None = None
    repository_versions: List[RepositoryVersion] | None = None

    if package.registry == REGISTRY_NPM:
        package_versions = load_npm_package_versions(package.name)

    if package_versions is None:
        raise ValueError(f"Cannot load package versions for '{package.name}'")

    # NOTE: there's depenedency on package_versions pulled
    if repository.provider == REPOSITORY_PROVIDER_GITHUB:
        repository_versions = load_github_code_versions(
            repository, package_versions)

    if repository_versions is None:
        raise ValueError(f"Cannot load repository versions for {package.name}")

    return package_versions, repository_versions


def aggregate_package_changes(registry_type: str, package_path: str, package_name: str):
    """
    Aggregate changes between two versions of a package regardless of the registry.
    """
    project = extract_project_info(registry_type, package_path)

    if package_name not in project.dependencies and package_name not in project.dev_dependencies:
        raise ValueError(
            f"Package {package_name} not found in project {project}")

    package = extract_package_info(registry_type, package_name)
    repository = load_github_repository(package.repo_url)
    package.repository = repository

    # Pull what is in the project file
    installed_version = project.installed_package_version(package_name)
    versions = load_package_versions(package, repository)

    import ipdb
    ipdb.set_trace()
    print(f"Installed Version: {installed_version}")
    print(f"Latest Version: {package.version}")

    pprint.pprint(project)
    pprint.pprint(package)
    pprint.pprint(repository)


def lookup_packages_to_check(package_json, package: str):
    # installed_spec = find_installed_version(package_json, package)
    # 4. Releases
    releases = fetch_releases(owner, repo)
    if not releases:
        # 4.1. Lookup up for tags
        # raise ValueError(f"No releases found on Github repository of package: {package}")
        tags = fetch_tags(owner, repo)
        if not tags:
            raise ValueError(
                f"No releases or tags found on Github repository of package: {package}")
        changes = filter_tags_between(
            tags, owner, repo, installed_version, latest_version)
    else:
        changes = filter_releases_between(
            releases, installed_version, latest_version)

    if not changes:
        raise ValueError(
            f"No changelog entries found between versions for package: {package}")

    return installed_version, latest_version, owner, repo, changes
