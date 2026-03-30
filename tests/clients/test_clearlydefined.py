# pylint: disable=protected-access
"""
Tests for ClearlyDefinedBatchStrategy in ossiq.clients.clearlydefined module.
"""

from unittest.mock import MagicMock

from ossiq.clients.client_clearlydefined import ClearlyDefinedBatchStrategy
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package


def make_package(name: str, registry: ProjectPackagesRegistry = ProjectPackagesRegistry.PYPI) -> Package:
    return Package(registry=registry, name=name, latest_version="1.0.0", next_version=None, repo_url=None)


class TestPrepareItem:
    def test_pypi_package(self):
        """Test coordinate format for a PyPI package."""
        # Arrange
        strategy = ClearlyDefinedBatchStrategy(MagicMock())
        pkg = make_package("requests", ProjectPackagesRegistry.PYPI)

        # Act
        coord = strategy.prepare_item((pkg, "2.28.2"))

        # Assert
        assert coord == "pypi/pypi/-/requests/2.28.2"

    def test_npm_unscoped_package(self):
        """Test coordinate format for an unscoped NPM package."""
        # Arrange
        strategy = ClearlyDefinedBatchStrategy(MagicMock())
        pkg = make_package("lodash", ProjectPackagesRegistry.NPM)

        # Act
        coord = strategy.prepare_item((pkg, "4.17.21"))

        # Assert
        assert coord == "npm/npmjs/-/lodash/4.17.21"

    def test_npm_scoped_package(self):
        """Test coordinate format for a scoped NPM package (@scope/name)."""
        # Arrange
        strategy = ClearlyDefinedBatchStrategy(MagicMock())
        pkg = make_package("@babel/core", ProjectPackagesRegistry.NPM)

        # Act
        coord = strategy.prepare_item((pkg, "7.22.0"))

        # Assert
        assert coord == "npm/npmjs/@babel/core/7.22.0"
