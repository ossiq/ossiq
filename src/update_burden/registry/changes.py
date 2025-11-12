"""
Aggregate all the changes around a package both
local and remote.
"""
import pprint

from typing import List

from ..settings import Settings
from ..domain.common import REGISTRY_NPM, REPOSITORY_PROVIDER_GITHUB
from ..domain.package import Package
from ..domain.project import Project
from ..domain.repository import Repository
from ..domain.version import PackageVersion, RepositoryVersion, Version, filter_versions_between
from .npm_api import (
    load_npm_package,
    parse_npm_project_info,
    load_npm_package_versions
)
from .gh_api import (
    is_github_repository,
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


def extract_repository_info(repository_url: str) -> Repository:
    """
    Extract repository info from a given repository URL.
    """
    if not repository_url:
        raise ValueError("Repository URL cannot be empty")

    if is_github_repository(repository_url):
        return load_github_repository(repository_url)

    raise ValueError(f"Unknown Repository Provider URL: {repository_url}")


def load_repository(package: Package) -> Repository:

    return load_github_repository(package.repo_url)


def load_package_versions(config: Settings, package: Package, repository: Repository,
                          installed_version: str) -> List[Version]:
    """
    Load package versions from a given registry.
    """
    package_versions: List[PackageVersion] | None = None
    repository_versions: List[RepositoryVersion] | None = None

    if package.registry == REGISTRY_NPM:
        package_versions = load_npm_package_versions(package.name)

    if package_versions is None:
        raise ValueError(f"Cannot load package versions for '{package.name}'")

    # NOTE: we don't need to pull all the versions, just the difference between
    # what we have and what is the latest available.
    tareget_versions = list(filter_versions_between(
        [p.version for p in package_versions],
        installed_version,
        package.version
    ))

    # filter out versions we don't need
    package_versions = [
        p for p in package_versions if p.version in tareget_versions]

    if repository.provider == REPOSITORY_PROVIDER_GITHUB:
        repository_versions = list(load_github_code_versions(
            repository,
            package_versions,
            config.github_token
        ))

    if repository_versions is None:
        raise ValueError(f"Cannot load repository versions for {package.name}")

    return package_versions, repository_versions


def aggregate_package_changes(config: Settings, registry_type: str,
                              package_path: str, package_name: str):
    """
    Aggregate changes between two versions of a package regardless of the registry.
    """
    project = extract_project_info(registry_type, package_path)

    if package_name not in project.dependencies and package_name not in project.dev_dependencies:
        raise ValueError(
            f"Package {package_name} not found in project {project}")

    package = extract_package_info(registry_type, package_name)
    repository = extract_repository_info(package.repo_url)
    package.repository = repository

    # Pull what is in the project file
    installed_version = project.installed_package_version(package_name)
    package_versions, repository_versions = load_package_versions(
        config, package, repository, installed_version
    )

    repo_versions_map = {
        version.version: version for version in repository_versions
    }

    versions = []
    for package_version in package_versions:

        # Assumption: identify changes only for versions available in the source code repository
        if package_version.version not in repo_versions_map:
            continue

        versions.append(Version(
            package_registry=package.registry,
            repository_provider=repository.provider,
            package_data=package_version,
            repository_data=repo_versions_map[package_version.version]
        ))

    if config.verbose:
        print(f"Installed Version: {installed_version}")
        print(f"Latest Version: {package.version}")

        for version in versions:
            # installed version
            if version.ref_previous is None:
                continue

            print(
                f"Diff {version.ref_previous} -> {version.version}: "
                f"{version.source_url} ({version.summary_description})"
            )

        # pprint.pprint(project)
        # pprint.pprint(package)
        # pprint.pprint(repository)
        # pprint.pprint(package_versions)
