"""
Reading package.json on its own, for projects with no lockfile: what a dependency block declares
becomes a Dependency tree one level deep.
"""

from collections import defaultdict
from typing import Any

from ossiq.adapters.package_managers.npm.constants import MANIFEST_FILE, PRODUCTION_SECTION, SECTION_CATEGORY
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource, Dependency
from ossiq.domain.version import classify_npm_specifier, normalize_version

# Peer before optional: the order `categories` lists them in for a manifest-only project, which
# differs from the lockfile's (see SECTION_CATEGORY) and is observable in the output.
NON_PRODUCTION_SECTIONS = ("devDependencies", "peerDependencies", "optionalDependencies")


def parse_npm_alias(version: str) -> tuple[str | None, str]:
    """
    Parse an npm alias specifier into (canonical_name, constraint).

    "npm:lodash@~4.17.0"   -> ("lodash",      "~4.17.0")
    "npm:chalk@4.1.2"      -> ("chalk",        "4.1.2")
    "npm:@scope/pkg@^1.0"  -> ("@scope/pkg",   "^1.0")
    "^4.18.0"              -> (None,            "^4.18.0")  (not an alias, pass-through)
    """
    if version.startswith("npm:"):
        without_prefix = version[4:]  # e.g. "chalk@4.1.2" or "@scope/pkg@^1.0.0"
        at_idx = without_prefix.rfind("@")
        if at_idx > 0:  # package name must be non-empty
            return without_prefix[:at_idx], without_prefix[at_idx + 1 :]
    return None, version


def make_manifest_dependency(name: str, version: str, categories: list[str]) -> Dependency:
    """Build a Dependency from a package.json entry (no lockfile needed)."""
    canonical_name, constraint = parse_npm_alias(version)
    return Dependency(
        name=name,
        canonical_name=canonical_name or name,
        version_installed=normalize_version(constraint),
        version_defined=version,
        categories=categories,
        constraint_info=ConstraintSource(type=classify_npm_specifier(constraint), source_file=MANIFEST_FILE),
    )


def parse_package_json(project_data: dict[str, Any]) -> Dependency:
    """Extract dependencies and categories from a decoded package.json.

    Production dependencies land in `dependencies`; a package declared only in dev, peer or optional
    sections lands in `optional_dependencies`. Either way it carries a category for every
    non-production section that names it.
    """
    categories: dict[str, list[str]] = defaultdict(list)
    for section in NON_PRODUCTION_SECTIONS:
        for name in project_data.get(section, {}):
            categories[name].append(SECTION_CATEGORY[section])

    dependencies = {
        name: make_manifest_dependency(name, spec, categories.get(name, []))
        for name, spec in project_data.get(PRODUCTION_SECTION, {}).items()
    }
    optional_dependencies: dict[str, Dependency] = {}
    for section in NON_PRODUCTION_SECTIONS:
        for name, spec in project_data.get(section, {}).items():
            if name not in dependencies and name not in optional_dependencies:
                optional_dependencies[name] = make_manifest_dependency(name, spec, categories.get(name, []))

    return Dependency(
        name=project_data.get("name", ""),
        canonical_name=project_data.get("name", ""),
        version_installed=project_data.get("version", ""),
        dependencies=dependencies,
        optional_dependencies=optional_dependencies,
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=MANIFEST_FILE),
    )
