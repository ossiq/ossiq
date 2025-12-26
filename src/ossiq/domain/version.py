"""
Module to operate with package versions
"""

import re
from dataclasses import dataclass
from functools import cmp_to_key

import semver

# Version is unpublished from the Package Registry
VERSION_NO_DIFF = 10
# Version installed and the latest in the Registry are the same
VERSION_LATEST = 0
# Installed version is a major version behind
VERSION_DIFF_MAJOR = 5
# Installd version is a minor version behind
VERSION_DIFF_MINOR = 4
# Installed version is patch version behind
VERSION_DIFF_PATCH = 3
# Installed version is pre-release version behind (same meaning as VERSION_LATEST)
VERSION_DIFF_PRERELEASE = 2
# Installed version is build version behind (same meaning as VERSION_LATEST)
VERSION_DIFF_BUILD = 1

VERSION_DIFF_TYPES_MAP = {
    "DIFF_MAJOR": VERSION_DIFF_MAJOR,
    "DIFF_MINOR": VERSION_DIFF_MINOR,
    "DIFF_PATCH": VERSION_DIFF_PATCH,
    "DIFF_PRERELEASE": VERSION_DIFF_PRERELEASE,
    "DIFF_BUILD": VERSION_DIFF_BUILD,
    "NO_DIFF": VERSION_NO_DIFF,
    "LATEST": VERSION_LATEST,
}

VERSINO_INVERSED_DIFF_TYPES_MAP = {val: key for key, val in VERSION_DIFF_TYPES_MAP.items()}


@dataclass
class VersionsDifference:
    version1: str
    version2: str
    diff_index: int
    diff_name: str


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
    author: User | None
    authored_at: str
    committer: User | None
    committed_at: str | None

    def __repr__(self):
        return f"Commit(sha='{self.sha}', author='{self.commit_user_name}', message = '{self.simplified_message}')"

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
    license: str | None
    package_url: str
    dependencies: dict[str, str]
    dev_dependencies: dict[str, str] | None = None
    runtime_requirements: dict[str, str] | None = None
    description: str | None = None
    published_date_iso: str | None = None
    unpublished_date_iso: str | None = None
    is_published: bool = True


@dataclass
class RepositoryVersion:
    """
    Partial version information typically pulled from source code repository.
    """

    version_source_type: str
    version: str
    commits: list[Commit] | None = None
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

    def __init__(
        self,
        package_registry: str,
        repository_provider: str,
        package_data: PackageVersion,
        repository_data: RepositoryVersion,
    ):
        assert repository_data is not None, "Repository version info cannot be None"
        # FIXME: fix validation here with custom exceptions + types from domain.common
        # assert package_registry in PACKAGE_REGISTRIES, \
        #     f"Invalid package registry {package_registry}"
        # assert repository_provider in REPOSITORY_PROVIDERS, \
        #     f"Invalid repository provider {repository_provider}"

        self.package_registry = package_registry
        self.repository_provider = repository_provider
        self.package_data = package_data
        self.repository_data = repository_data

        self._summary_description = None

    def __repr__(self):
        return f"Version(version='{self.version}', registr={self.package_registry}, repo={self.repository_provider})"

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
    return semver.Version.parse(v1).compare(semver.Version.parse(v2))


def sort_versions(versions: list[PackageVersion]) -> list[PackageVersion]:
    """
    Sorts a list of semantically versioned strings.
    """
    return sorted(versions, key=cmp_to_key(lambda v1, v2: compare_versions(v1.version, v2.version)))


def difference_versions(v1_str: str | None, v2_str: str | None) -> VersionsDifference:
    """Helper to split version strings and find the index where they first differ."""

    if not v1_str or not v2_str:
        return VersionsDifference(
            v1_str if v1_str else "N/A",
            v2_str if v2_str else "N/A",
            VERSION_NO_DIFF,
            diff_name=VERSINO_INVERSED_DIFF_TYPES_MAP[VERSION_NO_DIFF],
        )

    v1 = semver.Version.parse(v1_str)
    v2 = semver.Version.parse(v2_str)

    diff_index = VERSION_NO_DIFF

    if v1_str == v2_str:
        diff_index = VERSION_LATEST
    if v1.major != v2.major:
        diff_index = VERSION_DIFF_MAJOR
    elif v1.minor != v2.minor:
        diff_index = VERSION_DIFF_MINOR
    elif v1.patch != v2.patch:
        diff_index = VERSION_DIFF_PATCH
    elif v1.prerelease != v2.prerelease:
        diff_index = VERSION_DIFF_PRERELEASE
    elif v1.build != v2.build:
        diff_index = VERSION_DIFF_BUILD

    # The diff_index indicates the first differing part of the semantic version.
    # 0: major, 1: minor, 2: patch, 3: prerelease, 4: build.
    # This is used for highlighting the most significant difference in the HTML template.

    return VersionsDifference(str(v1), str(v2), diff_index, diff_name=VERSINO_INVERSED_DIFF_TYPES_MAP[diff_index])
