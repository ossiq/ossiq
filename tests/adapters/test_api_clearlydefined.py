# pylint: disable=protected-access
"""
Tests for LicenseApiClearlyDefined in ossiq.adapters.api_clearlydefined module.
"""

from unittest.mock import MagicMock, patch

import pytest

from ossiq.adapters.api_clearlydefined import LicenseApiClearlyDefined
from ossiq.clients.batch import BatchClient
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package


def make_package(name: str, registry: ProjectPackagesRegistry = ProjectPackagesRegistry.PYPI) -> Package:
    return Package(registry=registry, name=name, latest_version="1.0.0", next_version=None, repo_url=None)


class TestExtractLicense:
    def test_returns_declared_license_when_present(self):
        """Test that licensed.declared is returned when available."""
        # Arrange
        api = LicenseApiClearlyDefined(MagicMock())
        definition = {"licensed": {"declared": "Apache-2.0"}}

        # Act
        result = api._extract_license(definition)

        # Assert
        assert result == "Apache-2.0"

    def test_falls_back_to_discovered_when_no_declared(self):
        """Test fallback to discovered.expressions[0] when declared is absent."""
        # Arrange
        api = LicenseApiClearlyDefined(MagicMock())
        definition = {"licensed": {"facets": {"core": {"discovered": {"expressions": ["MIT", "MIT AND Apache-2.0"]}}}}}

        # Act
        result = api._extract_license(definition)

        # Assert
        assert result == "MIT"

    def test_returns_none_when_no_license_data(self):
        """Test that None is returned when definition has no license info."""
        # Arrange
        api = LicenseApiClearlyDefined(MagicMock())

        # Act
        result = api._extract_license({})

        # Assert
        assert result is None

    def test_declared_takes_priority_over_discovered(self):
        """Test that declared license takes priority over discovered expressions."""
        # Arrange
        api = LicenseApiClearlyDefined(MagicMock())
        definition = {
            "licensed": {
                "declared": "Apache-2.0",
                "facets": {"core": {"discovered": {"expressions": ["MIT"]}}},
            }
        }

        # Act
        result = api._extract_license(definition)

        # Assert
        assert result == "Apache-2.0"


class TestGetLicensesBatch:
    def test_empty_input_returns_empty_dict(self):
        """Test that an empty input list returns an empty dict without calling run_batch."""
        # Arrange
        api = LicenseApiClearlyDefined(MagicMock())

        # Act
        with patch.object(BatchClient, "run_batch") as mock_run:
            result = api.get_licenses_batch([])

        # Assert
        assert result == {}
        mock_run.assert_not_called()

    def test_returns_correct_mapping_for_single_pypi_package(self):
        """Test that a PyPI package result is keyed by (package.name, version) with SPDX license."""
        # Arrange
        pkg = make_package("requests", ProjectPackagesRegistry.PYPI)
        version = "2.28.2"
        coord = "pypi/pypi/-/requests/2.28.2"
        chunk_data = {coord: {"licensed": {"declared": "Apache-2.0"}}}
        api = LicenseApiClearlyDefined(MagicMock())

        # Act
        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_licenses_batch([(pkg, version)])

        # Assert
        assert result == {("requests", "2.28.2"): "Apache-2.0"}

    def test_returns_none_for_unknown_package(self):
        """Test that None is returned for packages not found in ClearlyDefined."""
        # Arrange
        pkg = make_package("obscure-internal-pkg", ProjectPackagesRegistry.PYPI)
        version = "1.0.0"
        api = LicenseApiClearlyDefined(MagicMock())

        # Act
        with patch.object(BatchClient, "run_batch", return_value=iter([{}])):
            result = api.get_licenses_batch([(pkg, version)])

        # Assert
        assert result == {("obscure-internal-pkg", "1.0.0"): None}

    def test_merges_results_from_multiple_chunks(self):
        """Test that license results from multiple yielded chunks are combined."""
        # Arrange
        pkgs = [
            (make_package("requests", ProjectPackagesRegistry.PYPI), "2.28.2"),
            (make_package("lodash", ProjectPackagesRegistry.NPM), "4.17.21"),
        ]
        chunk1 = {"pypi/pypi/-/requests/2.28.2": {"licensed": {"declared": "Apache-2.0"}}}
        chunk2 = {"npm/npmjs/-/lodash/4.17.21": {"licensed": {"declared": "MIT"}}}
        api = LicenseApiClearlyDefined(MagicMock())

        # Act
        with patch.object(BatchClient, "run_batch", return_value=iter([chunk1, chunk2])):
            result = api.get_licenses_batch(pkgs)

        # Assert
        assert result == {
            ("requests", "2.28.2"): "Apache-2.0",
            ("lodash", "4.17.21"): "MIT",
        }

    @pytest.mark.parametrize(
        "package_name,version,registry,expected_coord",
        [
            ("requests", "2.28.2", ProjectPackagesRegistry.PYPI, "pypi/pypi/-/requests/2.28.2"),
            ("lodash", "4.17.21", ProjectPackagesRegistry.NPM, "npm/npmjs/-/lodash/4.17.21"),
            ("@babel/core", "7.22.0", ProjectPackagesRegistry.NPM, "npm/npmjs/@babel/core/7.22.0"),
        ],
    )
    def test_coordinate_lookup_per_ecosystem(self, package_name, version, registry, expected_coord):
        """Test that each ecosystem's coordinate is used to look up the merged result."""
        # Arrange
        pkg = make_package(package_name, registry)
        chunk_data = {expected_coord: {"licensed": {"declared": "MIT"}}}
        api = LicenseApiClearlyDefined(MagicMock())

        # Act
        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_data])):
            result = api.get_licenses_batch([(pkg, version)])

        # Assert
        assert result[(package_name, version)] == "MIT"
