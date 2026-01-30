"""
Service for crawling and analyzing transitive dependencies.
"""

from dataclasses import dataclass, field

from rich.console import Console

from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ProjectMetrics
from ossiq.unit_of_work import core as unit_of_work

console = Console()


@dataclass
class TransitiveDependencyInfo:
    """Metrics record for a transitive dependency."""

    package_name: str
    installed_version: str
    latest_version: str | None
    versions_diff_index: VersionsDifference
    version_specifier: str  # How the parent depends on this package (e.g., ">=1.0,<2.0")
    is_pinned: bool  # True if specifier is an exact version pin (e.g., "==1.2.3")
    parent_package: str  # The direct dependency that requires this transitive dep
    time_lag_days: int | None = None
    releases_lag: int | None = None


@dataclass
class TransitiveDependencyTree:
    """Container for transitive dependency analysis results."""

    project_name: str
    packages_registry: str
    project_path: str
    transitive_packages: list[TransitiveDependencyInfo]
    errors: list[str] = field(default_factory=list)


# def is_pinned_version(specifier: str) -> bool:
#     """
#     Detect if a version specifier is an exact pin.

#     Exact pins can cause dependency conflicts and make upgrades difficult.
#     Examples of pinned versions: "==1.2.3", "1.2.3" (no operator)
#     Examples of non-pinned: ">=1.0", "~=1.2", ">=1.0,<2.0"
#     """
#     if not specifier:
#         return False

#     specifier = specifier.strip()

#     # If it starts with == and has no other operators, it's pinned
#     if specifier.startswith("==") and "," not in specifier:
#         return True

#     # If it's just a bare version number (no operators), treat as pinned
#     # This handles cases like "1.2.3" without any operator
#     if specifier and specifier[0].isdigit() and "," not in specifier:
#         # Check if there are any comparison operators
#         operators = [">=", "<=", "!=", "~=", ">", "<", "="]
#         if not any(op in specifier for op in operators):
#             return True

#     return False


# def parse_iso(datetime_str: str | None) -> datetime | None:
#     """Parse ISO datetime string to datetime object."""
#     if datetime_str:
#         return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))
#     return None


# def calculate_time_lag(installed_date_iso: str | None, latest_date_iso: str | None) -> int | None:
#     """Calculate time lag in days between two version publication dates."""
#     installed_date = parse_iso(installed_date_iso)
#     latest_date = parse_iso(latest_date_iso)

#     if installed_date and latest_date:
#         return (latest_date - installed_date).days

#     return None


def tree(
    uow: unit_of_work.AbstractProjectUnitOfWork,
    scan_metrics: ProjectMetrics,
) -> TransitiveDependencyTree | None:
    """
    Crawl and analyze transitive dependencies for a project.

    Uses the dependency tree from the lockfile to identify transitive dependencies,
    then fetches minimal metrics (installed vs latest version) for each.

    Args:
        uow: Unit of work providing access to package manager and registry
        scan_metrics: Results from direct dependency scan

    Returns:
        TransitiveDependencyTree with metrics for all transitive dependencies
    """

    # with uow:
    #     project_info = uow.packages_manager.project_info()
    #     dep_tree = uow.packages_manager.dependency_tree()

    #     # Build set of direct dependency names for quick lookup
    #     direct_deps = set(project_info.dependencies.keys())
    #     optional_deps = set(project_info.optional_dependencies.keys())
    #     all_direct_deps = direct_deps | optional_deps

    #     # Get all installed packages from the lockfile
    #     installed_packages = uow.packages_manager.installed_packages()
    #     all_packages_in_lockfile = set(installed_packages.keys())

    #     # Track processed transitive deps to avoid duplicates
    #     processed_transitive: dict[str, TransitiveDependencyInfo] = {}
    #     analysis_errors: list[str] = []

    #     # Use a stack for DFS traversal of the dependency tree
    #     # Each item is a tuple: (parent_name, dep_name)
    #     stack: list[tuple[str, str]] = []

    #     # Start traversal with direct dependencies
    #     for pkg_record in scan_metrics.production_packages + scan_metrics.optional_packages:
    #         stack.append((project_info.name, pkg_record.package_name))

    #     # Cache for package versions to avoid redundant API calls
    #     package_versions_cache = {}
    #     import ipdb

    #     ipdb.set_trace()
    #     while stack:
    #         parent_name, dep_name = stack.pop()

    #         # Skip if it's a direct dependency (already analyzed)
    #         if dep_name in all_direct_deps:
    #             # Still need to traverse its children
    #             for child_dep in dep_tree.get(dep_name, []):
    #                 stack.append((dep_name, child_dep))
    #             continue

    #         # Skip if already processed
    #         if dep_name in processed_transitive:
    #             continue

    #         # The dep should be in the lockfile if it's a transitive dep
    #         if dep_name not in all_packages_in_lockfile:
    #             analysis_errors.append(f"Package '{dep_name}' found in dependency tree but not in lockfile packages.")
    #             continue

    #         # Get installed version from the lockfile
    #         installed_version = installed_packages.get(dep_name)
    #         if not installed_version:
    #             analysis_errors.append(f"Could not determine installed \
    #                  version for package '{dep_name}' from lockfile.")
    #             continue

    #         try:
    #             package_info = uow.packages_registry.package_info(dep_name)
    #             if dep_name not in package_versions_cache:
    #                 package_versions_cache[dep_name] = list(uow.packages_registry.package_versions(dep_name))
    #         except Exception as e:
    #             analysis_errors.append(f"Could not retrieve package info for '{dep_name}': {e}")
    #             continue

    #         # Get version specifier from parent's dependencies
    #         version_specifier = "*"
    #         if parent_name == project_info.name:
    #             if dep_name in project_info.dependencies:
    #                 version_specifier = project_info.dependencies[dep_name].version_defined or "*"
    #             elif dep_name in project_info.optional_dependencies:
    #                 version_specifier = project_info.optional_dependencies[dep_name].version_defined or "*"
    #         else:
    #             parent_version_str = installed_packages.get(parent_name)
    #             if parent_version_str:
    #                 if parent_name not in package_versions_cache:
    #                     try:
    #                         package_versions_cache[parent_name] = list(
    #                             uow.packages_registry.package_versions(parent_name)
    #                         )
    #                     except Exception as e:
    #                         analysis_errors.append(f"Could not retrieve versions for parent '{parent_name}': {e}")
    #                         package_versions_cache[parent_name] = []

    #                 parent_versions = package_versions_cache[parent_name]
    #                 parent_package_version = next((v for v in parent_versions
    #                                                if v.version == parent_version_str), None)
    #                 if parent_package_version and parent_package_version.dependencies:
    #                     version_specifier = parent_package_version.dependencies.get(dep_name, "*")

    #         version_delta = transitive_package_delta(uow, package_info, installed_version)

    #         time_lag = None
    #         releases_lag = None

    #         if version_delta.installed and version_delta.latest:
    #             installed_pkg = version_delta.installed.package_data
    #             latest_pkg = version_delta.latest.package_data
    #             time_lag = calculate_time_lag(installed_pkg.published_date_iso, latest_pkg.published_date_iso)

    #             if dep_name in package_versions_cache:
    #                 installed_date = parse_iso(installed_pkg.published_date_iso)
    #                 latest_date = parse_iso(latest_pkg.published_date_iso)
    #                 if installed_date and latest_date:
    #                     releases_between = [
    #                         v
    #                         for v in package_versions_cache[dep_name]
    #                         if installed_date < (parse_iso(v.published_date_iso) or installed_date) <= latest_date
    #                     ]
    #                     releases_lag = len(releases_between)

    #         processed_transitive[dep_name] = TransitiveDependencyInfo(
    #             package_name=dep_name,
    #             installed_version=installed_version,
    #             latest_version=package_info.latest_version,
    #             versions_diff_index=uow.packages_registry.difference_versions(
    #                 installed_version, package_info.latest_version
    #             ),
    #             version_specifier=version_specifier,
    #             is_pinned=is_pinned_version(version_specifier),
    #             parent_package=parent_name,
    #             time_lag_days=time_lag,
    #             releases_lag=releases_lag,
    #         )

    #         # Add children to the stack to continue traversal
    #         for child_dep in dep_tree.get(dep_name, []):
    #             stack.append((dep_name, child_dep))

    #     return TransitiveDependencyTree(
    #         project_name=project_info.name,
    #         packages_registry=project_info.package_registry.value,
    #         project_path=project_info.project_path or "",
    #         transitive_packages=list(processed_transitive.values()),
    #         errors=analysis_errors,
    #     )
    pass
