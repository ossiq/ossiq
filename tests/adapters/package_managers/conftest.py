"""Fixtures shared by the npm adapter tests and the tests of the npm/ modules."""

import json
import tempfile
from pathlib import Path

import pytest

from ossiq.settings import Settings


# ============================================================================
# Fixtures
# ============================================================================
@pytest.fixture
def settings():
    """Create Settings instance for testing."""
    return Settings()


@pytest.fixture
def temp_project_dir():
    """Create a temporary directory for test projects."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def npm_project_with_lockfile(temp_project_dir):
    """
    Create a temporary NPM project with package.json and package-lock.json files.

    Returns a project with:
    - Main dependencies: express, lodash
    - Dev dependencies: jest, eslint
    - Optional dependencies: fsevents
    - Peer dependencies: react
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    # Create package.json
    package_json_content = {
        "name": "test-npm-project",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"},
        "devDependencies": {"jest": ">=29.0.0", "eslint": "^8.0.0"},
        "optionalDependencies": {"fsevents": "^2.3.2"},
        "peerDependencies": {"react": "^18.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    # Create package-lock.json (lockfile version 3)
    lockfile_content = {
        "name": "test-npm-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": "test-npm-project",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"},
                "devDependencies": {"jest": ">=29.0.0", "eslint": "^8.0.0"},
                "optionalDependencies": {"fsevents": "^2.3.2"},
                "peerDependencies": {"react": "^18.0.0"},
            },
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/jest": {"version": "29.7.0", "dev": True},
            "node_modules/eslint": {"version": "8.56.0", "dev": True},
            "node_modules/fsevents": {"version": "2.3.3", "optional": True},
            "node_modules/react": {"version": "18.2.0", "peer": True},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


@pytest.fixture
def npm_project_dual_category_deps(temp_project_dir):
    """
    Create NPM project where a dependency appears in multiple categories.

    This tests the edge case where one package is both a main dependency
    and in optional/dev/peer dependencies.
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {
        "name": "dual-category-project",
        "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.21"},
        "devDependencies": {"lodash": "^4.17.21", "jest": "^29.0.0"},
        "optionalDependencies": {"fsevents": "^2.3.2"},
        "peerDependencies": {"jest": "^29.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "dual-category-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "dual-category-project",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21"},
                "devDependencies": {"lodash": "^4.17.21", "jest": "^29.0.0"},
            },
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/jest": {"version": "29.7.0"},
            "node_modules/fsevents": {"version": "2.3.3"},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir
