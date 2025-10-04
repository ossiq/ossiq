import pprint
from .package import Package, REGISTRY_NPM
from .repository import Repository
from .project import Project, PROJECT_TYPE_NPM, PROJECT_TYPE_PYPI
from .npm_api import fetch_npm_info, parse_npm_project_info
from .versions import normalize_version


def extract_project_info(registry_type: str, path: str) -> Project:
    """
    Extract project info from a given path.
    """
    if registry_type == REGISTRY_NPM:
        return parse_npm_project_info(path)

    raise ValueError(f"Unknown registry type: {registry_type}")


def extract_package_info(registry_type: str, project: Project, package_name: str) -> Package:
    """
    Extract package info from a given project.
    """
    if registry_type == REGISTRY_NPM:
        return fetch_npm_info(package_name)

    raise ValueError(f"Unknown registry type: {registry_type}")


def aggregate_package_changes(registry_type: str, package_path: str, package_name: str):
    """
    Aggregate changes between two versions of a package regardless of the registry.
    """
    project = extract_project_info(registry_type, package_path)

    if package_name not in project.dependencies and package_name not in project.dev_dependencies:
        raise ValueError(
            f"Package {package_name} not found in project {project}")

    package = extract_package_info(registry_type, project, package_name)

    installed_version = project.installed_package_version(package_name)

    print(f"Installed Version: {installed_version}")
    print(f"Latest Version: {package.version}")

    pprint.pprint(project)
    pprint.pprint(package)


def lookup_packages_to_check(package_json, package: str):
    # installed_spec = find_installed_version(package_json, package)

    installed_version = normalize_version(installed_spec)

    # 2. Get NPM info
    npm_info = fetch_npm_info(package)
    latest_version = npm_info.get("dist-tags", {}).get("latest")
    if not latest_version:
        raise ValueError(
            f"Could not determine latest version of package:{package}")

    # 3. Repo info
    repo_url = extract_github_repo_url(npm_info)
    gh = normalize_github_url(repo_url or "")
    if not gh:
        raise ValueError(
            f"No GitHub repository found in npm metadata for package:{package}")

    owner, repo = gh

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
