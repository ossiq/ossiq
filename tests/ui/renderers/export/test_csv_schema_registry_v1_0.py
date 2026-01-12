"""
Tests for CSV export schema registry with Frictionless Table Schema.

This test suite follows pytest best practices:
- AAA pattern (Arrange-Act-Assert) for clear test structure
- Parametrization to reduce test duplication
- Fixtures for reusable setup/teardown
- Single responsibility per test
- Mocking external dependencies where appropriate
"""

from pathlib import Path

import pytest

from ossiq.domain.common import ExportCsvSchemaVersion
from ossiq.ui.renderers.export.csv_schema_registry import CsvSchemaRegistry, csv_schema_registry


@pytest.fixture
def registry():
    """Create a CsvSchemaRegistry instance for tests."""
    return CsvSchemaRegistry()


@pytest.fixture
def v1_0_summary_schema(registry):
    """Load v1.0 summary schema for tests."""
    return registry.load_schema(ExportCsvSchemaVersion.V1_0, "summary")


@pytest.fixture
def v1_0_packages_schema(registry):
    """Load v1.0 packages schema for tests."""
    return registry.load_schema(ExportCsvSchemaVersion.V1_0, "packages")


@pytest.fixture
def v1_0_cves_schema(registry):
    """Load v1.0 CVEs schema for tests."""
    return registry.load_schema(ExportCsvSchemaVersion.V1_0, "cves")


class TestCsvSchemaRegistryV10:
    """Test suite for CSV schema registry with Frictionless Table Schema."""

    @pytest.mark.parametrize("schema_type", ["summary", "packages", "cves"])
    def test_get_schema_path_returns_valid_path_for_v1_0(self, registry, schema_type):
        """Test getting schema path for v1.0 returns existing file.

        AAA Pattern:
        - Arrange: Registry fixture and parametrized schema type
        - Act: Get schema path for v1.0
        - Assert: Path is valid and file exists
        """
        # Act
        path = registry.get_schema_path(ExportCsvSchemaVersion.V1_0, schema_type)

        # Assert
        assert isinstance(path, Path)
        assert path.name == f"{schema_type}-schema-v1.0.json"
        assert path.exists()

    def test_get_schema_path_raises_for_invalid_type(self, registry):
        """Test getting schema path raises ValueError for invalid type.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act & Assert: Attempt to get invalid schema type
        """
        # Act & Assert
        with pytest.raises(ValueError, match="Schema type 'invalid' not found"):
            registry.get_schema_path(ExportCsvSchemaVersion.V1_0, "invalid")

    def test_load_summary_schema_returns_valid_content(self, v1_0_summary_schema):
        """Test loading v1.0 summary schema returns valid Table Schema dict.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Schema is already loaded
        - Assert: Verify schema content structure
        """
        # Assert
        assert isinstance(v1_0_summary_schema, dict)
        assert "fields" in v1_0_summary_schema
        assert isinstance(v1_0_summary_schema["fields"], list)
        assert len(v1_0_summary_schema["fields"]) == 11

        # Verify first field structure
        first_field = v1_0_summary_schema["fields"][0]
        assert first_field["name"] == "schema_version"
        assert first_field["type"] == "string"

    def test_load_packages_schema_returns_valid_content(self, v1_0_packages_schema):
        """Test loading v1.0 packages schema returns valid Table Schema dict.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Schema is already loaded
        - Assert: Verify schema content structure
        """
        # Assert
        assert isinstance(v1_0_packages_schema, dict)
        assert "fields" in v1_0_packages_schema
        assert isinstance(v1_0_packages_schema["fields"], list)
        assert len(v1_0_packages_schema["fields"]) == 8

        # Verify first field structure
        first_field = v1_0_packages_schema["fields"][0]
        assert first_field["name"] == "package_name"
        assert first_field["type"] == "string"

        # Verify primary key is defined
        assert "primaryKey" in v1_0_packages_schema
        assert v1_0_packages_schema["primaryKey"] == ["package_name"]

    def test_load_cves_schema_returns_valid_content(self, v1_0_cves_schema):
        """Test loading v1.0 CVEs schema returns valid Table Schema dict.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Schema is already loaded
        - Assert: Verify schema content structure
        """
        # Assert
        assert isinstance(v1_0_cves_schema, dict)
        assert "fields" in v1_0_cves_schema
        assert isinstance(v1_0_cves_schema["fields"], list)
        assert len(v1_0_cves_schema["fields"]) == 10

        # Verify first field structure
        first_field = v1_0_cves_schema["fields"][0]
        assert first_field["name"] == "cve_id"
        assert first_field["type"] == "string"

        # Verify foreign key is defined
        assert "foreignKeys" in v1_0_cves_schema
        assert len(v1_0_cves_schema["foreignKeys"]) == 1
        fk = v1_0_cves_schema["foreignKeys"][0]
        assert fk["fields"] == ["package_name"]
        assert fk["reference"]["resource"] == "packages"
        assert fk["reference"]["fields"] == ["package_name"]

    @pytest.mark.parametrize("schema_type", ["summary", "packages", "cves"])
    def test_validate_schema_passes_for_valid_schemas(self, registry, schema_type):
        """Test schema validation passes for all v1.0 schemas.

        AAA Pattern:
        - Arrange: Registry fixture and parametrized schema type
        - Act: Validate schema against Frictionless spec
        - Assert: Validation passes without errors
        """
        # Act
        is_valid, errors = registry.validate_schema(ExportCsvSchemaVersion.V1_0, schema_type)

        # Assert
        assert is_valid is True, f"Schema validation failed with errors: {errors}"
        assert len(errors) == 0

    def test_schema_fields_have_required_properties(self, v1_0_summary_schema):
        """Test all schema fields have required name and type properties.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Iterate over fields
        - Assert: Each field has name and type
        """
        # Act & Assert
        for field in v1_0_summary_schema["fields"]:
            assert "name" in field, f"Field missing name: {field}"
            assert "type" in field, f"Field {field.get('name', 'unknown')} missing type"
            assert isinstance(field["name"], str)
            assert isinstance(field["type"], str)

    def test_get_latest_version_returns_v1_0(self, registry):
        """Test registry returns correct latest schema version.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get latest version
        - Assert: Version is v1.0
        """
        # Act
        latest = registry.get_latest_version()

        # Assert
        assert latest == ExportCsvSchemaVersion.V1_0

    def test_list_versions_includes_v1_0(self, registry):
        """Test listing all registered versions includes v1.0.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: List all versions
        - Assert: v1.0 is in the list
        """
        # Act
        versions = registry.list_versions()

        # Assert
        assert isinstance(versions, list)
        assert len(versions) >= 1
        assert ExportCsvSchemaVersion.V1_0 in versions

    def test_list_schema_types_returns_all_types(self, registry):
        """Test listing schema types for v1.0 returns all three types.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: List schema types for v1.0
        - Assert: All types are present
        """
        # Act
        types = registry.list_schema_types(ExportCsvSchemaVersion.V1_0)

        # Assert
        assert isinstance(types, list)
        assert len(types) == 3
        assert "summary" in types
        assert "packages" in types
        assert "cves" in types

    def test_global_registry_instance_accessible(self):
        """Test global registry singleton is accessible and functional.

        AAA Pattern:
        - Arrange: Global csv_schema_registry instance
        - Act: Get schema path from global instance
        - Assert: Instance is valid and path exists
        """
        # Act
        path = csv_schema_registry.get_schema_path(ExportCsvSchemaVersion.V1_0, "summary")

        # Assert
        assert isinstance(csv_schema_registry, CsvSchemaRegistry)
        assert path.exists()

    def test_validate_csv_with_valid_file(self, registry, tmp_path):
        """Test CSV validation passes for valid CSV file.

        AAA Pattern:
        - Arrange: Create valid summary CSV file
        - Act: Validate CSV against schema
        - Assert: Validation passes without errors
        """
        # Arrange
        csv_file = tmp_path / "test-summary.csv"
        csv_content = (
            "schema_version,export_timestamp,project_name,project_path,project_registry,"
            "total_packages,production_packages,development_packages,packages_with_cves,total_cves,packages_outdated\n"
            "1.0,2025-01-09T12:00:00,test-project,/path/to/project,npm,10,8,2,3,5,4\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")

        # Act
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "summary")

        # Assert
        assert is_valid is True, f"Validation failed with errors: {errors}"
        assert len(errors) == 0

    def test_validate_csv_fails_with_wrong_columns(self, registry, tmp_path):
        """Test CSV validation fails when columns don't match schema.

        AAA Pattern:
        - Arrange: Create CSV with wrong column headers
        - Act: Validate CSV against schema
        - Assert: Validation fails with error
        """
        # Arrange
        csv_file = tmp_path / "test-summary.csv"
        csv_content = """wrong_column,another_column
value1,value2
"""
        csv_file.write_text(csv_content, encoding="utf-8-sig")

        # Act
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "summary")

        # Assert
        assert is_valid is False
        assert len(errors) > 0

    def test_validate_csv_fails_with_wrong_row_count_for_summary(self, registry, tmp_path):
        """Test CSV validation fails when summary CSV has wrong row count.

        AAA Pattern:
        - Arrange: Create summary CSV with multiple rows (should be 1)
        - Act: Validate CSV against schema
        - Assert: Validation fails with row count error
        """
        # Arrange
        csv_file = tmp_path / "test-summary.csv"
        csv_content = (
            "schema_version,export_timestamp,project_name,project_path,project_registry,"
            "total_packages,production_packages,development_packages,packages_with_cves,total_cves,packages_outdated\n"
            "1.0,2025-01-09T12:00:00,test-project,/path/to/project,npm,10,8,2,3,5,4\n"
            "1.0,2025-01-09T12:00:00,test-project2,/path/to/project2,pypi,20,15,5,5,10,8\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")

        # Act
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "summary")

        # Assert
        assert is_valid is False
        assert len(errors) > 0
        assert "should have exactly 1 data row" in errors[0]

    def test_validate_csv_with_empty_packages(self, registry, tmp_path):
        """Test CSV validation passes for packages CSV with headers only (no rows).

        AAA Pattern:
        - Arrange: Create packages CSV with headers but no data rows
        - Act: Validate CSV against schema
        - Assert: Validation passes (empty packages is valid)
        """
        # Arrange
        csv_file = tmp_path / "test-packages.csv"
        csv_content = (
            "package_name,dependency_type,is_optional_dependency,installed_version,"
            "latest_version,time_lag_days,releases_lag,cve_count\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")

        # Act
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "packages")

        # Assert
        assert is_valid is True, f"Validation failed with errors: {errors}"
        assert len(errors) == 0

    def test_validate_csv_with_valid_packages(self, registry, tmp_path):
        """Test CSV validation passes for valid packages CSV.

        AAA Pattern:
        - Arrange: Create valid packages CSV file
        - Act: Validate CSV against schema
        - Assert: Validation passes without errors
        """
        # Arrange
        csv_file = tmp_path / "test-packages.csv"
        csv_content = (
            "package_name,dependency_type,is_optional_dependency,installed_version,"
            "latest_version,time_lag_days,releases_lag,cve_count\n"
            "react,production,false,17.0.2,18.2.0,245,12,1\n"
            "lodash,development,true,4.17.20,4.17.21,180,1,0\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")

        # Act
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "packages")

        # Assert
        assert is_valid is True, f"Validation failed with errors: {errors}"
        assert len(errors) == 0

    def test_validate_csv_with_valid_cves(self, registry, tmp_path):
        """Test CSV validation passes for valid CVEs CSV.

        AAA Pattern:
        - Arrange: Create valid CVEs CSV file
        - Act: Validate CSV against schema
        - Assert: Validation passes without errors
        """
        # Arrange
        csv_file = tmp_path / "test-cves.csv"
        csv_content = (
            "cve_id,package_name,package_registry,source,severity,summary,"
            "affected_versions,all_cve_ids,published,link\n"
            "GHSA-test-1234,react,npm,GHSA,HIGH,Test vulnerability,<18.0.0,"
            "CVE-2023-12345|GHSA-test-1234,2023-03-15T00:00:00,https://example.com\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")

        # Act
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "cves")

        # Assert
        assert is_valid is True, f"Validation failed with errors: {errors}"
        assert len(errors) == 0
