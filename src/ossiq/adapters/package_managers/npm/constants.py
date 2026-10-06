"""
Vocabulary shared by every part of the npm adapter: the manifest file name and the dependency
sections of package.json / package-lock.json with the category each one tags a package with.
"""

from ossiq.adapters.package_managers.dependency_tree import CATEGORY_PEER

MANIFEST_FILE = "package.json"

CATEGORIES_DEV = "development"
CATEGORIES_OPTIONAL = "optional"
CATEGORIES_PEER = CATEGORY_PEER
CATEGORIES_OVERRIDDEN = "overridden"

# Production dependencies carry no category.
PRODUCTION_SECTION = "dependencies"

# Non-production section name -> the category it tags a dependency with. Iteration order is the
# lockfile's, which is the order categories accumulate on a node.
SECTION_CATEGORY: dict[str, str] = {
    "devDependencies": CATEGORIES_DEV,
    "optionalDependencies": CATEGORIES_OPTIONAL,
    "peerDependencies": CATEGORIES_PEER,
}

DEP_SECTIONS = (PRODUCTION_SECTION, *SECTION_CATEGORY)
