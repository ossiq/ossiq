"""
Tests for frontend_build.replace_report_data_with_placeholder().

Validates the regex-based HTML transformation that converts the built
Vue.js SPA into a reusable template by replacing the dummy JSON data
with a placeholder sentinel.
"""

import sys
from pathlib import Path

import pytest

# frontend_build.py lives at project root, not in a Python package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from hatch_build import REPORT_DATA_PLACEHOLDER, replace_report_data_with_placeholder


class TestReplaceReportDataWithPlaceholder:
    """Test suite for the HTML placeholder replacement function."""

    def test_placeholder_replaces_dummy_json(self):
        """Test that dummy JSON content is replaced with the placeholder.

        AAA Pattern:
        - Arrange: HTML with a script tag containing dummy JSON
        - Act: Run replacement
        - Assert: Dummy JSON is gone, placeholder is present
        """
        # Arrange
        html = '<html><script type="json/oss-iq-report">{"metadata":{"schema_version":"1.0"}}</script></html>'

        # Act
        result = replace_report_data_with_placeholder(html)

        # Assert
        assert '{"metadata":{"schema_version":"1.0"}}' not in result
        assert REPORT_DATA_PLACEHOLDER in result

    def test_replacement_preserves_script_tags(self):
        """Test that opening and closing script tags remain intact.

        AAA Pattern:
        - Arrange: HTML with the data script tag
        - Act: Run replacement
        - Assert: Script tag structure is preserved around placeholder
        """
        # Arrange
        html = '<script type="json/oss-iq-report">{"dummy": true}</script>'

        # Act
        result = replace_report_data_with_placeholder(html)

        # Assert
        expected = f'<script type="json/oss-iq-report">{REPORT_DATA_PLACEHOLDER}</script>'
        assert result == expected

    def test_raises_error_when_no_script_tag_found(self):
        """Test that a ValueError is raised when the script tag is missing.

        AAA Pattern:
        - Arrange: HTML without the data script tag
        - Act & Assert: Verify ValueError is raised
        """
        # Arrange
        html = "<html><body>no script tag here</body></html>"

        # Act & Assert
        with pytest.raises(ValueError, match="No <script"):
            replace_report_data_with_placeholder(html)

    def test_preserves_surrounding_html(self):
        """Test that HTML content outside the script tag is not modified.

        AAA Pattern:
        - Arrange: HTML with content before and after the script tag
        - Act: Run replacement
        - Assert: Surrounding content is unchanged
        """
        # Arrange
        html = (
            "<!DOCTYPE html><html><head><title>Test</title></head><body>"
            '<div id="app"></div>'
            '<script type="module">console.log("app")</script>'
            '<script type="json/oss-iq-report">{"data": 1}</script>'
            "</body></html>"
        )

        # Act
        result = replace_report_data_with_placeholder(html)

        # Assert
        assert "<title>Test</title>" in result
        assert '<div id="app"></div>' in result
        assert '<script type="module">console.log("app")</script>' in result
        assert '{"data": 1}' not in result

    def test_handles_large_json_content(self):
        """Test replacement works with large JSON blobs similar to real builds.

        AAA Pattern:
        - Arrange: HTML with a large JSON payload
        - Act: Run replacement
        - Assert: Placeholder replaces the entire payload
        """
        # Arrange
        large_json = '{"packages":' + str([{"name": f"pkg-{i}"} for i in range(100)]) + "}"
        html = f'<script type="json/oss-iq-report">{large_json}</script>'

        # Act
        result = replace_report_data_with_placeholder(html)

        # Assert
        assert large_json not in result
        assert REPORT_DATA_PLACEHOLDER in result

    def test_custom_placeholder_value(self):
        """Test that a custom placeholder string can be used.

        AAA Pattern:
        - Arrange: HTML with script tag and a custom placeholder
        - Act: Run replacement with custom placeholder
        - Assert: Custom placeholder is injected
        """
        # Arrange
        html = '<script type="json/oss-iq-report">{"dummy": true}</script>'
        custom_placeholder = "{{CUSTOM_PLACEHOLDER}}"

        # Act
        result = replace_report_data_with_placeholder(html, placeholder=custom_placeholder)

        # Assert
        assert custom_placeholder in result
        assert REPORT_DATA_PLACEHOLDER not in result

    def test_default_placeholder_constant_value(self):
        """Test that the default placeholder constant has the expected value."""
        # Assert
        assert REPORT_DATA_PLACEHOLDER == "__OSSIQ_REPORT_DATA__"
