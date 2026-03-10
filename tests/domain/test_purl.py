"""
Tests for build_purl() in domain/common.py.

Covers the PURL (Package URL) construction logic per ECMA-386:
- Standard packages for each supported registry
- NPM scoped packages requiring percent-encoding
"""

import pytest

from ossiq.domain.common import ProjectPackagesRegistry, build_purl


class TestBuildPurl:
    """Unit tests for the build_purl() utility function."""

    @pytest.mark.parametrize(
        "registry,name,version,expected",
        [
            (ProjectPackagesRegistry.PYPI, "requests", "2.25.1", "pkg:pypi/requests@2.25.1"),
            (ProjectPackagesRegistry.PYPI, "django", "4.2.0", "pkg:pypi/django@4.2.0"),
            (ProjectPackagesRegistry.NPM, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
            (ProjectPackagesRegistry.NPM, "react", "18.2.0", "pkg:npm/react@18.2.0"),
        ],
    )
    def test_standard_packages_produce_correct_purl(self, registry, name, version, expected):
        """Test PURL construction for standard (non-scoped) package names.

        AAA Pattern:
        - Arrange: registry enum, plain package name, version string
        - Act: call build_purl()
        - Assert: output matches expected PURL format pkg:{type}/{name}@{version}
        """
        # Act
        result = build_purl(registry, name, version)

        # Assert
        assert result == expected

    @pytest.mark.parametrize(
        "name,version,expected",
        [
            ("@babel/core", "7.0.0", "pkg:npm/%40babel%2Fcore@7.0.0"),
            ("@scope/pkg", "1.0.0", "pkg:npm/%40scope%2Fpkg@1.0.0"),
            ("@types/node", "20.0.0", "pkg:npm/%40types%2Fnode@20.0.0"),
        ],
    )
    def test_npm_scoped_packages_are_percent_encoded(self, name, version, expected):
        """Test that NPM scoped packages (@scope/name) are correctly percent-encoded.

        Per PURL spec §7.1, '@' must be encoded as '%40' and '/' as '%2F'
        in the name component.

        AAA Pattern:
        - Arrange: scoped NPM package name
        - Act: call build_purl() with NPM registry
        - Assert: '@' and '/' in the name are percent-encoded in the output
        """
        # Act
        result = build_purl(ProjectPackagesRegistry.NPM, name, version)

        # Assert
        assert result == expected

    def test_purl_starts_with_pkg_scheme(self):
        """Test that all PURLs start with the 'pkg:' scheme."""
        # Act
        result = build_purl(ProjectPackagesRegistry.PYPI, "requests", "2.25.1")

        # Assert
        assert result.startswith("pkg:")

    def test_version_is_not_encoded(self):
        """Test that the version portion is appended as-is after '@'."""
        # Arrange
        version = "1.2.3-beta.1"

        # Act
        result = build_purl(ProjectPackagesRegistry.NPM, "mylib", version)

        # Assert
        assert result.endswith(f"@{version}")

    def test_pypi_type_identifier(self):
        """Test that PyPI packages use 'pypi' as the PURL type."""
        # Act
        result = build_purl(ProjectPackagesRegistry.PYPI, "requests", "2.25.1")

        # Assert
        assert result.startswith("pkg:pypi/")

    def test_npm_type_identifier(self):
        """Test that NPM packages use 'npm' as the PURL type."""
        # Act
        result = build_purl(ProjectPackagesRegistry.NPM, "lodash", "4.17.21")

        # Assert
        assert result.startswith("pkg:npm/")
