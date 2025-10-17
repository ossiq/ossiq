"""
Module to operate with package versions
"""
import re
from dataclasses import dataclass
from typing import List, Dict, Iterable
from functools import cmp_to_key

import semver

from .common import (
    PACKAGE_REGISTRIES,
    REPOSITORY_PROVIDERS,
)


@dataclass(frozen=True)
class User:
    """Class to contains user information."""
    id: int
    username: str
    email: str
    display_name: str
    profile_url: str

    def __repr__(self):
        return f"""User(login='{self.username}', name='{self.display_name}')"""


@dataclass(frozen=True)
class Commit:
    """Class to contains commit information."""
    sha: str
    message: str
    author: User
    authored_at: str
    committer: User | None
    committed_at: str | None

    def __repr__(self):
        return f"Commit(sha='{self.sha}', author='{self.commit_user_name}', "\
            f"message='{self.simplified_message}')"

    @property
    def commit_user_name(self):
        if self.author:
            return self.author.display_name
        if self.committer:
            return self.committer.display_name
        return "<N/A>"

    @property
    def simplified_message(self):
        # TODO: would be great to actually sum up changes, especially with
        return self.message.split("\n")[0]


@dataclass(frozen=True)
class PackageVersion:
    """
    Partial version information typically pulled from package registry.
    """
    version: str
    dependencies: Dict[str, str]
    license: str
    package_url: str
    runtime_requirements: Dict[str, str] | None = None
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
    ref_previous: str | None = None
    ref_name: str | None = None
    release_name: str | None = None
    release_notes: str | None = None
    source_url: str | None = None
    # NOTE: patches could be pretty sizable so let's not load it every time
    patch_url: str | None = None


class Version:
    """
    Class to contains aggregated version information from both sides: 
    Package Registry and Source Code Repository
    """

    package_registry: str
    repository_provider: str

    package_data: PackageVersion
    repository_data: RepositoryVersion

    _summary_description: str | None

    def __init__(self, package_registry: str, repository_provider: str,
                 package_data: PackageVersion, repository_data: RepositoryVersion):

        assert repository_data is not None, \
            "Repository version info cannot be None"
        assert package_registry in PACKAGE_REGISTRIES, \
            f"Invalid package registry {package_registry}"
        assert repository_provider in REPOSITORY_PROVIDERS, \
            f"Invalid repository provider {repository_provider}"

        self.package_registry = package_registry
        self.repository_provider = repository_provider
        self.package_data = package_data
        self.repository_data = repository_data

        self._summary_description = None

    def __repr__(self):
        return f"Version(version='{self.version}', "\
            f"registr={self.package_registry}, "\
            f"repo={self.repository_provider})"

    @property
    def version(self):
        return self.package_data.version

    @property
    def ref_previous(self):
        return self.repository_data.ref_previous

    @property
    def source_url(self):
        return self.repository_data.source_url

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


def sort_versions(versions: List[PackageVersion]) -> List[PackageVersion]:
    """
    Sorts a list of semantically versioned strings.
    """
    return sorted(versions, key=cmp_to_key(lambda v1, v2: compare_versions(v1.version, v2.version)))
