"""
Tests for HTML scan renderer.

This test suite follows pytest best practices:
- AAA pattern (Arrange-Act-Assert) for clear test structure
- Parametrization to reduce test duplication
- Fixtures for reusable setup/teardown
- Single responsibility per test
"""

import json
from pathlib import Path

import pytest

from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.domain.cve import CVE, CveDatabase, Severity
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ScanResult, ScanRecord
from ossiq.settings import Settings
from ossiq.ui.renderers.scan.html import HtmlScanRenderer


@pytest.fixture
def settings():
    """Create Settings instance for tests."""
    return Settings()


@pytest.fixture
def sample_cve():
    """Create a sample CVE for testing."""
    return CVE(
        id="GHSA-test-1234",
        cve_ids=("CVE-2023-12345",),
        source=CveDatabase.GHSA,
        package_name="react",
        package_registry=ProjectPackagesRegistry.NPM,
        summary="Test vulnerability",
        severity=Severity.HIGH,
        affected_versions=("<18.0.0",),
        published="2023-03-15T00:00:00Z",
        link="https://example.com/advisory",
    )


@pytest.fixture
def sample_project_metrics_record(sample_cve):
    """Create a sample ScanRecord for testing."""
    return ScanRecord(
        package_name="react",
        is_optional_dependency=False,
        installed_version="17.0.2",
        latest_version="18.2.0",
        versions_diff_index=VersionsDifference(
            version1="17.0.2", version2="18.2.0", diff_index=5, diff_name="DIFF_MAJOR"
        ),
        time_lag_days=245,
        releases_lag=12,
        cve=[sample_cve],
    )


@pytest.fixture
def sample_project_metrics(sample_project_metrics_record):
    """Create realistic ScanResult for testing."""
    return ScanResult(
        project_name="test-project",
        project_path="/path/to/test-project",
        packages_registry=ProjectPackagesRegistry.NPM.value,
        production_packages=[sample_project_metrics_record],
        optional_packages=[],
    )


@pytest.fixture
def output_file(tmp_path):
    """Create output file path fixture with automatic cleanup."""
    output_path = tmp_path / "report.html"
    yield output_path
    # Cleanup happens automatically via tmp_path


class TestHtmlScanRenderer:
    """Test suite for HTML scan renderer."""

    @pytest.mark.parametrize(
        "command,user_interface_type,expected",
        [
            (Command.SCAN, UserInterfaceType.HTML, True),
            (Command.EXPORT, UserInterfaceType.HTML, False),
            (Command.SCAN, UserInterfaceType.CONSOLE, False),
            (Command.SCAN, UserInterfaceType.JSON, False),
        ],
    )
    def test_supports_command_presentation_combinations(self, command, user_interface_type, expected):
        """Verify renderer correctly identifies supported command/presentation type combinations.

        AAA Pattern:
        - Arrange: Parametrized test inputs
        - Act: Call supports() method
        - Assert: Verify expected support result
        """
        # Act
        result = HtmlScanRenderer.supports(command, user_interface_type)

        # Assert
        assert result == expected

    def test_basic_render_creates_valid_html_file(self, output_file, sample_project_metrics, settings):
        """Test basic HTML render creates a valid file.

        AAA Pattern:
        - Arrange: Set up renderer and output path
        - Act: Render the HTML
        - Assert: Verify file exists and contains expected HTML structure
        """
        # Arrange
        renderer = HtmlScanRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Assert
        assert output_file.exists()
        html_content = output_file.read_text()
        assert "<!DOCTYPE html>" in html_content or "<html" in html_content

    def test_rendered_html_contains_json_data(self, output_file, sample_project_metrics, settings):
        """Test rendered HTML contains embedded JSON data.

        AAA Pattern:
        - Arrange: Set up renderer and render HTML
        - Act: Extract HTML content
        - Assert: Verify JSON script tag exists and placeholder is replaced
        """
        # Arrange
        renderer = HtmlScanRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Assert
        html_content = output_file.read_text()
        assert '<script type="json/oss-iq-report">' in html_content
        assert "__OSSIQ_REPORT_DATA__" not in html_content  # Placeholder should be replaced

    def test_embedded_json_is_valid(self, output_file, sample_project_metrics, settings):
        """Test embedded JSON data is valid and parseable.

        AAA Pattern:
        - Arrange: Set up renderer and render HTML
        - Act: Extract and parse JSON from script tag
        - Assert: Verify JSON is valid and contains expected data
        """
        # Arrange
        renderer = HtmlScanRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Act
        html_content = output_file.read_text()
        # Extract JSON from script tag
        json_start = html_content.find('<script type="json/oss-iq-report">') + len('<script type="json/oss-iq-report">')
        json_end = html_content.find("</script>", json_start)
        json_content = html_content[json_start:json_end]

        # Parse JSON
        data = json.loads(json_content)

        # Assert
        assert "metadata" in data
        assert "project" in data
        assert data["project"]["name"] == "test-project"

    def test_embedded_json_contains_expected_structure(self, output_file, sample_project_metrics, settings):
        """Test embedded JSON contains all expected top-level keys.

        AAA Pattern:
        - Arrange: Set up renderer and render HTML
        - Act: Extract and parse JSON from HTML
        - Assert: Verify all expected keys are present
        """
        # Arrange
        renderer = HtmlScanRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Act
        html_content = output_file.read_text()
        json_start = html_content.find('<script type="json/oss-iq-report">') + len('<script type="json/oss-iq-report">')
        json_end = html_content.find("</script>", json_start)
        json_content = html_content[json_start:json_end]
        data = json.loads(json_content)

        # Assert
        expected_keys = ["metadata", "project", "summary", "production_packages", "development_packages"]
        assert all(key in data for key in expected_keys)

    def test_project_name_placeholder_replaced_in_destination(self, tmp_path, sample_project_metrics, settings):
        """Test {project_name} placeholder is replaced with actual project name.

        AAA Pattern:
        - Arrange: Set up renderer with placeholder in destination path
        - Act: Render HTML
        - Assert: Verify file created with actual project name
        """
        # Arrange
        renderer = HtmlScanRenderer(settings)
        output_template = tmp_path / "report_{project_name}.html"

        # Act
        renderer.render(sample_project_metrics, destination=str(output_template))

        # Assert
        expected_file = tmp_path / "report_test-project.html"
        assert expected_file.exists()

    def test_raises_exception_when_destination_directory_not_exists(self, sample_project_metrics, settings):
        """Test raises DestinationDoesntExist for invalid directory.

        AAA Pattern:
        - Arrange: Set up renderer with nonexistent destination
        - Act & Assert: Verify exception is raised
        """
        # Arrange
        renderer = HtmlScanRenderer(settings)

        # Act & Assert
        with pytest.raises(DestinationDoesntExist):
            renderer.render(sample_project_metrics, destination="/nonexistent/dir/report.html")

    def test_unicode_characters_handled_correctly(self, output_file, settings):
        """Test HTML export handles Unicode characters correctly.

        AAA Pattern:
        - Arrange: Create metrics with Unicode project name
        - Act: Render HTML
        - Assert: Verify Unicode preserved correctly in embedded JSON
        """
        # Arrange
        metrics = ScanResult(
            project_name="tëst-ünïcødé",
            project_path="/path/to/project",
            packages_registry="NPM",
            production_packages=[],
            optional_packages=[],
        )
        renderer = HtmlScanRenderer(settings)

        # Act
        renderer.render(metrics, destination=str(output_file))
        html_content = output_file.read_text()

        # Assert
        # Extract JSON and verify Unicode is preserved
        json_start = html_content.find('<script type="json/oss-iq-report">') + len('<script type="json/oss-iq-report">')
        json_end = html_content.find("</script>", json_start)
        json_content = html_content[json_start:json_end]
        data = json.loads(json_content)
        assert data["project"]["name"] == "tëst-ünïcødé"

    def test_spa_template_exists(self):
        """Test that the SPA template file exists.

        AAA Pattern:
        - Arrange: Calculate expected SPA template path
        - Act: Check if file exists
        - Assert: Verify file is present
        """
        # Arrange
        import ossiq.ui.renderers.scan.html

        spa_template_path = (
            Path(ossiq.ui.renderers.scan.html.__file__).parent.parent.parent / "html_templates" / "spa_app.html"
        )

        # Act & Assert
        assert spa_template_path.exists(), f"SPA template not found at {spa_template_path}"

    def test_rendered_html_contains_package_data(self, output_file, sample_project_metrics, settings):
        """Test rendered HTML contains package data in embedded JSON.

        AAA Pattern:
        - Arrange: Set up renderer with sample package data
        - Act: Render HTML and extract JSON
        - Assert: Verify package data is present
        """
        # Arrange
        renderer = HtmlScanRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Act
        html_content = output_file.read_text()
        json_start = html_content.find('<script type="json/oss-iq-report">') + len('<script type="json/oss-iq-report">')
        json_end = html_content.find("</script>", json_start)
        json_content = html_content[json_start:json_end]
        data = json.loads(json_content)

        # Assert
        assert len(data["production_packages"]) == 1
        pkg = data["production_packages"][0]
        assert pkg["package_name"] == "react"
        assert pkg["installed_version"] == "17.0.2"
        assert pkg["latest_version"] == "18.2.0"

    def test_rendered_html_contains_cve_data(self, output_file, sample_project_metrics, settings):
        """Test rendered HTML contains CVE data in embedded JSON.

        AAA Pattern:
        - Arrange: Set up renderer with sample CVE data
        - Act: Render HTML and extract JSON
        - Assert: Verify CVE data is present
        """
        # Arrange
        renderer = HtmlScanRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Act
        html_content = output_file.read_text()
        json_start = html_content.find('<script type="json/oss-iq-report">') + len('<script type="json/oss-iq-report">')
        json_end = html_content.find("</script>", json_start)
        json_content = html_content[json_start:json_end]
        data = json.loads(json_content)

        # Assert
        pkg = data["production_packages"][0]
        assert len(pkg["cve"]) == 1
        assert pkg["cve"][0]["severity"] == "HIGH"
        assert pkg["cve"][0]["source"] == "GHSA"
        assert pkg["cve"][0]["id"] == "GHSA-test-1234"
