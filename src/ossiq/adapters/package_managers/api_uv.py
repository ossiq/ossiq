"""
Support of UV package manager
"""
import os
import tomllib
from collections import namedtuple

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.domain.ecosystem import UV, PackageManagerType
from ossiq.domain.project import Project
from ossiq.settings import Settings


UvProject = namedtuple("UvProject", ["manifest", "lockfile"])


class PackageManagerPythonUv(AbstractPackageManagerApi):
    """
    Abstract Package Manager to extract installed versions
    of packages from different package managers.
    """

    settings: Settings
    package_manager_type: PackageManagerType = UV
    project_path: str = None

    @staticmethod
    def project_files(project_path: str) -> UvProject:
        return UvProject(
            os.path.join(project_path, UV.primary_manifest.name),
            os.path.join(project_path, UV.lockfile.name)
        )

    @staticmethod
    def has_package_manager(project_path: str) -> bool:
        """
        Detect that UV package manager is used in a project_path.
        """
        project_files = PackageManagerPythonUv.project_files(project_path)

        if os.path.exists(project_files.manifest) and os.path.exists(project_files.lockfile):
            return True

        return False

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

    def project_info(self) -> Project:
        """
        Extract project dependencies using file format from a specific
        package manager.       
        """

        project_files = PackageManagerPythonUv.project_files(self.project_path)

        with open(project_files.manifest, "rb") as f:
            pyproject_data = tomllib.load(open(project_files.manifest, "rb"))

        with open(project_files.lockfile, "rb") as f:
            uv_lock_data = tomllib.load(f)

        project_name = pyproject_data.get("project", {}).get(
            "name", os.path.basename(self.project_path))

        # TODO: figure out project package name (from pyproject.toml), then pull categories
        categories = {
            "main": [],
            "test": [],
            "docs": []
        }

        for dist in uv_lock_data.get("requires-dist", []):
            marker = dist.get("marker", "")
            name = dist["name"]

            if "extra == 'test'" in marker:
                categories["test"].append(name)
            elif "extra == 'docs'" in marker:
                categories["docs"].append(name)
            elif not marker:
                categories["main"].append(name)
        import ipdb
        ipdb.set_trace()
        # # TODO: refactor Project to support multiple categories of dependencies
        # return Project(
        #     package_manager=self.package_manager,
        #     name=project_name,
        #     project_path=project_path,
        #     dependencies=dependencies,
        #     dev_dependencies=dev_dependencies,
        # )

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
