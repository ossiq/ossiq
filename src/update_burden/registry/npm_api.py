"""
Module to operate with NPM registry
"""
import json
import os
from typing import List
import requests

from ..domain.common import REGISTRY_NPM, PROJECT_TYPE_NPM
from ..domain.package import Package
from ..domain.project import Project
from ..domain.version import PackageVersion, normalize_version

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
