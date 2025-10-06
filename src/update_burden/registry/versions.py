"""
Module to operate with package versions
"""
import re
from dataclasses import dataclass
from typing import List, Dict, Iterable

import semver

from .common import (
    PACKAGE_REGISTRIES,
    REPOSITORY_PROVIDERS,
    VERSION_DATA_SOURCE_GITHUB_RELEASES,
    VERSION_DATA_SOURCE_GITHUB_TAGS
)


@dataclass
class User:
    """Class to contains user information."""
    id: int
    login: str
    email: str
    name: str
    html_url: str

    def __repr__(self):
        return f"""User(login='{self.login}', name='{self.name}')"""


@dataclass
class Commit:
    """Class to contains commit information."""
    sha: str
    message: str
    author: User
    author_date: str
    committer: User | None
    committer_date: str | None

    def __repr__(self):
        return f"Commit(sha='{self.sha}', author='{self.commit_user_name}', "\
            f"message='{self.simplified_message}')"

    @property
    def commit_user_name(self):
        if self.author:
            return self.author.name
        if self.committer:
            return self.committer.name
        return "<N/A>"

    @property
    def simplified_message(self):
        # TODO: would be great to actually sum up changes, especially with
        return self.message.split("\n")[0]


@dataclass
class PackageVersion:
    """
    Partial version information typically pulled from package registry.
    """
    version: str
    dependencies: Dict[str, str]
    license: str
    package_version_url: str
    engine_versions: Dict[str, str] | None = None
    dev_dependencies: Dict[str, str] | None = None
    description: str | None = None


@dataclass
class RepositoryVersion:
    """
    Partial version information typically pulled from source code repository.    
    """

    version_source_type: str
    commits: List[Commit]
    version: str
    prev_version: str | None = None
    name: str | None = None
    description: str | None = None
    repository_version_url: str | None = None
    # NOTE: patches could be pretty sizable so let's not load it every time
    patch_url: str | None = None


class Version:
    """
    Class to contains aggregated version information from both sides: 
    Package Registry and Source Code Repository
    """

    # version source type in the repository, could be github tag, github release etc
    version_source_type: str

    # package registry (could be NPM, PyPi etc.)
    package_registry: str

    # source code repository provider (github, bitbucket potentially ...)
    repository_provider: str

    # version comes from package registry (NPM, PyPi etc.)
    version: str

    # raw data comes from the repository, could be list of commits or separate message
    commits: List[Commit]

    dependencies: Dict[str, str]
    dev_dependencies: Dict[str, str]

    # could be minimum node or python version
    engine_versions: Dict[str, str]

    version_description: str | None
    summary_description: str | None

    license: str
    package_version_url: str
    repository_version_url: str

    def __init__(self, package_registry: str, repository_provider: str,
                 package_version_info: PackageVersion, repository_version_info: RepositoryVersion):

        version_source_type = repository_version_info.version_source_type
        assert version_source_type in (VERSION_DATA_SOURCE_GITHUB_RELEASES,
                                       VERSION_DATA_SOURCE_GITHUB_TAGS), \
            f"Invalid data source type {version_source_type}"
        assert package_registry in PACKAGE_REGISTRIES, \
            f"Invalid package registry {package_registry}"
        assert repository_provider in REPOSITORY_PROVIDERS, \
            f"Invalid repository provider {repository_provider}"

        self.version_source_type = version_source_type
        self.package_registry = package_registry
        self.repository_provider = repository_provider

        self.version = package_version_info.version
        self.dependencies = package_version_info.dependencies
        self.dev_dependencies = package_version_info.dev_dependencies
        self.engine_versions = package_version_info.engine_versions
        self.version_description = package_version_info.description

        self.commits = repository_version_info.commits

        self.package_version_url = package_version_info.package_version_url
        self.repository_version_url = repository_version_info.repository_version_url
        self.license = package_version_info.license

    def __repr__(self):
        return f"{self.data_source_type} Version(version='{self.version}', "\
            f"registr={self.package_registry}, "\
            f"repo={self.repository_provider}, license={self.license})"

    @property
    def summary_description(self):
        if self._summary_description is None:
            raise ValueError("Summary description not set yet")
        return self._summary_description

    @summary_description.setter
    def summary_description(self, summary: str):
        self._summary_description = summary


def normalize_version(spec: str) -> str:
    """
    Normalize version to feed into semver later on.
    TODO: likely semver could parse it better than the regexp:
          questinable vibecoded regexp.
    """
    if not spec:
        return spec
    m = re.search(r"\d+\.\d+\.\d+(?:[-+][^\s,]*)?", spec)
    if m:
        return m.group(0)
    return spec


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two versions leveraging semver.
    Potentially silent with try/catch and compare raw: (v1 > v2) - (v1 < v2)
    """
    return semver.compare(v1, v2)


def filter_versions_between(versions: list[str], installed: str, latest: str) -> Iterable[str]:
    """
    Filter out versions which we're interested in.
    """

    if installed == latest:
        return

    installed_norm, latest_norm = normalize_version(
        installed), normalize_version(latest)

    for version in sorted(versions):
        version_norm = normalize_version(version)
        if not version_norm:
            continue

        if compare_versions(version_norm, installed_norm) >= 0 and compare_versions(
                version_norm, latest_norm) <= 0:
            yield version
