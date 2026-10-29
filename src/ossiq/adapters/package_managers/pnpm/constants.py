"""
Vocabulary of the pnpm adapter: its workspace file, the lockfile's root importer and the sections
of an importer with the category each one tags a direct dependency with.
"""

from ossiq.adapters.package_managers.npm.constants import CATEGORIES_DEV, CATEGORIES_OPTIONAL, PRODUCTION_SECTION

WORKSPACE_FILE = "pnpm-workspace.yaml"

# Only the project's own importer is read; workspace members are out of scope.
ROOT_IMPORTER = "."

CATALOG_PROTOCOL = "catalog:"
DEFAULT_CATALOG = "default"

# Importer section -> the category it tags a direct dependency with. Production carries none.
IMPORTER_SECTION_CATEGORY: dict[str, str | None] = {
    PRODUCTION_SECTION: None,
    "devDependencies": CATEGORIES_DEV,
    "optionalDependencies": CATEGORIES_OPTIONAL,
}
